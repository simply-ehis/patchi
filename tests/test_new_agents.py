"""Tests for all new agents and utilities implemented in the feature expansion."""

from __future__ import annotations

import json
import tempfile
from datetime import date, timedelta
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from patchi.core.agents.base import AgentInput, AgentResult, AgentStatus, Finding, Severity
from patchi.core.agents.build_tool_validator import BuildToolValidatorAgent
from patchi.core.agents.cicd_generator import CICDGeneratorAgent
from patchi.core.agents.coverage_prioritizer import CoveragePrioritizerAgent
from patchi.core.agents.dead_code_hygiene import (
    DeadCodeHygieneAgent,
    _detect_duplicate_deps,
    _find_feature_flags,
)
from patchi.core.agents.dead_code_scanner import DeadCodeScanner
from patchi.core.agents.license_compliance import LicenseComplianceAgent
from patchi.core.agents.refactoring_agent import (
    RefactoringAgent,
    _detect_file_handle_leaks,
    _detect_interval_without_cleanup,
    _detect_modernization_candidates,
)
from patchi.core.agents.sbom_generator import SBOMGeneratorAgent
from patchi.core.agents.snapshot_drift_detector import SnapshotDriftDetectorAgent
from patchi.core.agents.spa_route_inventory import SPARouteInventoryAgent
from patchi.core.brain.baseline import (
    diff_baseline,
    load_baseline,
    save_baseline,
    update_baseline,
)
from patchi.core.brain.ignore_parser import (
    find_expired_ignores,
    findings_from_expired_ignores,
    scan_ignore_directives,
)
from patchi.core.brain.orphaned_endpoints import (
    FrontendCall,
    OrphanedEndpointResult,
    _normalize_path,
    findings_from_orphaned_endpoints,
    scan_frontend_calls,
)
from patchi.core.fix.code_fixer import CodeFixer
from patchi.core.fix.dead_code_remover import DeadCodeRemover
from patchi.core.fix.fix_agents import TypeFixer, _detect_language
from patchi.core.security.auth_audit_agent import AuthenticationAuditAgent
from patchi.core.security.authz_agent import AuthZAgent
from patchi.core.security.business_logic_agent import BusinessLogicAgent
from patchi.core.security.catch_block_auditor import CatchBlockAuditor
from patchi.core.security.env_var_validator import EnvVarValidator
from patchi.core.security.insecure_randomness_agent import InsecureRandomnessAgent
from patchi.core.security.security_taint import TaintAnalyzer
from patchi.core.security.session_management_agent import SessionManagementAgent
from patchi.core.testing.flake_detector_agent import (
    FlakeDetectorAgent,
    _detect_duration_outliers,
    _detect_flaky_tests,
    record_test_run,
)

# ── Test InsecureRandomnessAgent ────────────────────────────────────────────


class TestInsecureRandomnessAgent:
    def test_agent_metadata(self):
        agent = InsecureRandomnessAgent()
        assert agent.name == "InsecureRandomnessAgent"
        assert agent.group.value == "security"

    def test_detects_js_math_random(self):
        agent = InsecureRandomnessAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("const x = Math.random();")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.MEDIUM

    def test_security_context_elevation(self):
        agent = InsecureRandomnessAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "auth.js").write_text("const token = Math.random();")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            highs = [f for f in result.findings if f.severity == Severity.HIGH]
            assert len(highs) == 1

    def test_python_random_detected(self):
        agent = InsecureRandomnessAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import random; x = random.randint(1,10)")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            assert len(result.findings) >= 1

    def test_java_util_random_detected(self):
        agent = InsecureRandomnessAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AuthService.java").write_text("import java.util.Random; // for token generation")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            assert len(result.findings) >= 1


# ── Test CatchBlockAuditor ──────────────────────────────────────────────────


class TestCatchBlockAuditor:
    def test_agent_metadata(self):
        agent = CatchBlockAuditor()
        assert agent.name == "CatchBlockAuditor"
        assert agent.group.value == "security"

    def test_bare_except_python(self):
        agent = CatchBlockAuditor()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "handler.py").write_text("""
                try:
                    do_something()
                except:
                    pass
            """)
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            assert len(result.findings) >= 1

    def test_empty_catch_js(self):
        agent = CatchBlockAuditor()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "handler.js").write_text("""
                try {
                    doSomething();
                } catch (e) {}
            """)
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            assert len(result.findings) >= 1

    def test_go_ignored_error(self):
        agent = CatchBlockAuditor()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "handler.go").write_text("_ = doSomething() // error ignored")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            assert len(result.findings) >= 1

    def test_rust_unwrap(self):
        agent = CatchBlockAuditor()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "handler.rs").write_text("""
                fn main() {
                    let x = some_result.unwrap();
                }
            """)
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            assert len(result.findings) >= 1


# ── Test EnvVarValidator ────────────────────────────────────────────────────


class TestEnvVarValidator:
    def test_agent_metadata(self):
        agent = EnvVarValidator()
        assert agent.name == "EnvVarValidator"
        assert agent.group.value == "security"

    def test_undocumented_env_var(self):
        agent = EnvVarValidator()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import os; API_KEY = os.getenv('API_KEY')")
            (root / ".env.example").write_text("DATABASE_URL=postgres://localhost:5432/db")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            undocumented = [f for f in result.findings if f.type.startswith("undocumented_env_var")]
            assert len(undocumented) == 1

    def test_unvalidated_bare_access(self):
        agent = EnvVarValidator()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import os; DB_URL = os.environ['DB_URL']")
            (root / ".env.example").write_text("DB_URL=postgres://localhost:5432/db")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            bare = [f for f in result.findings if f.type.startswith("unvalidated_env_var")]
            assert len(bare) >= 1

    def test_env_var_with_default_not_unvalidated(self):
        agent = EnvVarValidator()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import os; x = os.getenv('X', 'default')")
            (root / ".env.example").write_text("X=some_value")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            unvalidated = [f for f in result.findings if f.type.startswith("unvalidated_env_var")]
            assert len(unvalidated) == 0


# ── Test SessionManagementAgent ──────────────────────────────────────────────


class TestSessionManagement:
    def test_agent_metadata(self):
        agent = SessionManagementAgent()
        assert agent.name == "SessionManagementAgent"
        assert agent.group.value == "security"

    def test_session_fixation_on_login(self):
        agent = SessionManagementAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "def login(req):\n    session['user_id'] = req.user.id\n    return ok\n"
            )
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            fixation = [f for f in result.findings if f.type == "session_fixation"]
            assert len(fixation) >= 1

    def test_missing_httponly_and_secure(self):
        agent = SessionManagementAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("response.set_cookie('sid', value)\n")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            types = {f.type for f in result.findings}
            assert "missing_httponly" in types
            assert "missing_secure_flag" in types

    def test_session_in_url(self):
        agent = SessionManagementAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("const url = 'http://site/home?session_id=abc123';\n")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            in_url = [f for f in result.findings if f.type == "session_in_url"]
            assert len(in_url) >= 1

    def test_insecure_localstorage_storage(self):
        agent = SessionManagementAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("localStorage.setItem('token', jwt)\n")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            storage = [f for f in result.findings if f.type == "insecure_session_storage"]
            assert len(storage) >= 1

    def test_user_controlled_session_id(self):
        agent = SessionManagementAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("session_id = request.args.get('sid')\n")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = agent.run(inp)
            uc = [f for f in result.findings if f.type == "user_controlled_session_id"]
            assert len(uc) >= 1


# ── Test AuthZAgent ──────────────────────────────────────────────────────────


class TestAuthZ:
    def test_agent_metadata(self):
        agent = AuthZAgent()
        assert agent.name == "AuthZAgent"
        assert agent.group.value == "security"

    def test_unauthenticated_route_flagged(self):
        agent = AuthZAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(
                "const app = require('express')();\n"
                "app.get('/api/users', (req, res) => { res.json([]); });\n"
            )
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={}, domain="web", purpose="web")
            result = agent.run(inp)
            assert result.status.value != "skipped"
            auth_findings = [
                f for f in result.findings
                if "authorization" in f.type or "auth" in f.type
            ]
            assert len(auth_findings) >= 1

    def test_authenticated_route_not_flagged(self):
        agent = AuthZAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text(
                "const app = require('express')();\n"
                "app.get('/api/users', authenticate, (req, res) => { res.json([]); });\n"
            )
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={}, domain="web", purpose="web")
            result = agent.run(inp)
            assert result.status.value != "skipped"
            missing_auth = [
                f for f in result.findings
                if f.type == "potential_missing_authorization_check"
            ]
            assert len(missing_auth) == 0


# ── Test AuthenticationAuditAgent ─────────────────────────────────────────────


class TestAuthenticationAudit:
    def test_agent_metadata(self):
        agent = AuthenticationAuditAgent()
        assert agent.name == "AuthenticationAuditAgent"
        assert agent.group.value == "security"

    def test_weak_hash_detected(self):
        agent = AuthenticationAuditAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import hashlib\npwd = hashlib.md5(password).hexdigest()\n")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={}, domain="web", purpose="web")
            result = agent.run(inp)
            assert result.status.value != "skipped"
            weak = [f for f in result.findings if f.type == "weak_password_hash"]
            assert len(weak) >= 1

    def test_hardcoded_session_secret(self):
        agent = AuthenticationAuditAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("SECRET_KEY = 'supersecretvalue123'\n")
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={}, domain="web", purpose="web")
            result = agent.run(inp)
            assert result.status.value != "skipped"
            secret = [f for f in result.findings if "secret" in f.message.lower() or "session_secret" in f.code_snippet.lower()]
            assert len(secret) >= 1

    def test_multilang_scanning(self):
        agent = AuthenticationAuditAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # JS auth endpoint with no rate limiting — must be caught cross-language.
            (root / "auth.js").write_text(
                "app.post('/login', (req, res) => { authenticate(req); });\n"
            )
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={}, domain="web", purpose="web")
            result = agent.run(inp)
            assert result.status.value != "skipped"
            rate = [f for f in result.findings if f.type == "missing_rate_limit"]
            assert len(rate) >= 1


# ── Test BusinessLogicAgent ───────────────────────────────────────────────────


class TestBusinessLogic:
    def test_agent_metadata(self):
        agent = BusinessLogicAgent()
        assert agent.name == "BusinessLogicAgent"
        assert agent.group.value == "security"

    def test_mass_assignment(self):
        agent = BusinessLogicAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "routes.py").write_text(
                "@app.route('/user/<id>')\n"
                "def update_user(id):\n"
                "    user = User.query.get(id)\n"
                "    user.update(request.json)\n"
                "    return user\n"
            )
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = AgentResult(agent_name=agent.name, agent_group=agent.group, status=AgentStatus.RUNNING)
            agent._run(inp, result)
            ma = [f for f in result.findings if f.type == "mass_assignment"]
            assert len(ma) >= 1

    def test_idor_and_state_transition_js(self):
        agent = BusinessLogicAgent()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.js").write_text(
                "router.get('/orders/{id}', (req, res) => {\n"
                "  const order = Order.find(req.params.id);\n"
                "  order.status = 'shipped';\n"
                "  order.save();\n"
                "  res.json(order);\n"
                "});\n"
            )
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
            result = AgentResult(agent_name=agent.name, agent_group=agent.group, status=AgentStatus.RUNNING)
            agent._run(inp, result)
            idor = [f for f in result.findings if f.type == "idor_missing_ownership_check"]
            state = [f for f in result.findings if f.type == "unvalidated_state_transition"]
            assert len(idor) >= 1
            assert len(state) >= 1


# ── Test Baseline Locking ───────────────────────────────────────────────────


class TestBaseline:
    def test_save_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
                Finding(agent="test", type="warn", severity=Severity.MEDIUM, file="b.py", line=5, message="ok"),
            ]
            snapshot = save_baseline(findings, root)
            assert snapshot.total_findings == 2
            assert snapshot.by_severity["high"] == 1
            assert snapshot.by_severity["medium"] == 1

            loaded = load_baseline(root)
            assert loaded is not None
            assert loaded.total_findings == 2

    def test_diff_new_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
            ]
            save_baseline(old, root)

            current = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
                Finding(agent="test", type="new", severity=Severity.LOW, file="c.py", line=3, message="new issue"),
            ]
            diff = diff_baseline(current, root)
            assert diff is not None
            assert diff.new_count == 1
            assert diff.total_current == 2
            assert diff.total_baseline == 1

    def test_diff_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
                Finding(agent="test", type="warn", severity=Severity.MEDIUM, file="b.py", line=2, message="old"),
            ]
            save_baseline(old, root)

            current = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
            ]
            diff = diff_baseline(current, root)
            assert diff is not None
            assert diff.resolved_count == 1
            assert diff.new_count == 0

    def test_no_baseline_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diff = diff_baseline([], root)
            assert diff is None

    def test_diff_with_dict_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
            ]
            save_baseline(old, root)

            current_dicts = [
                {"agent": "test", "type": "err", "severity": "high", "file": "a.py", "line": 1, "message": "bad"},
                {"agent": "test", "type": "new", "severity": "low", "file": "c.py", "line": 3, "message": "new"},
            ]
            diff = diff_baseline(current_dicts, root)  # type: ignore[arg-type]
            assert diff is not None
            assert diff.new_count == 1

    def test_update_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
            ]
            snapshot = update_baseline(findings, root)
            assert snapshot.total_findings == 1


# ── Test Ignore Parser ──────────────────────────────────────────────────────


class TestIgnoreParser:
    def test_scan_valid_directive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("// patchi-ignore: SECRET-SECURITY 2027-12-31")
            dirs = scan_ignore_directives(root)
            assert len(dirs) == 1
            assert dirs[0].rule == "SECRET-SECURITY"
            assert dirs[0].expired is False

    def test_expired_directive_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yesterday = (date.today() - timedelta(days=1)).isoformat()
            (root / "app.py").write_text(f"# patchi-ignore: SECRET-001 {yesterday}")
            expired = find_expired_ignores(root)
            assert len(expired) == 1

    def test_expired_directive_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            yesterday = (date.today() - timedelta(days=1)).isoformat()
            (root / "app.py").write_text(f"# patchi-ignore: SECRET-001 {yesterday}")
            findings = findings_from_expired_ignores(root)
            assert len(findings) == 1
            assert findings[0].type == "expired_ignore_directive"
            assert findings[0].severity == Severity.MEDIUM

    def test_python_hash_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("# patchi-ignore: RULE-001 2028-06-15")
            dirs = scan_ignore_directives(root)
            assert len(dirs) == 1
            assert dirs[0].rule == "RULE-001"

    def test_rust_block_comment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.rs").write_text("/* patchi-ignore: RULE-002 2028-06-15 */")
            dirs = scan_ignore_directives(root)
            assert len(dirs) == 1
            assert dirs[0].rule == "RULE-002"

    def test_no_directives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("x = 1")
            dirs = scan_ignore_directives(root)
            assert len(dirs) == 0


# ── Test Orphaned Endpoints ─────────────────────────────────────────────────


class TestOrphanedEndpoints:
    def test_normalize_path(self):
        assert _normalize_path("/api/users/42") == "/api/users/:param"
        assert _normalize_path("/api/users/abc-123-def") == "/api/users/abc-123-def"  # not uuid-like
        assert _normalize_path("/api/users/:id") == "/api/users/:param"
        assert _normalize_path("/api/users/{id}") == "/api/users/:param"
        assert _normalize_path("/api/users/[id]") == "/api/users/:param"
        assert _normalize_path("/api/users") == "/api/users"
        assert _normalize_path("/api/users/") == "/api/users"

    def test_scan_frontend_calls_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("""
                fetch('/api/users');
                fetch('/api/users/42');
            """)
            calls = scan_frontend_calls(root)
            assert len(calls) == 2
            assert calls[0].url == "/api/users"
            assert calls[1].url == "/api/users/42"

    def test_scan_frontend_calls_axios(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.ts").write_text("axios.get('/api/data')")
            calls = scan_frontend_calls(root)
            assert len(calls) == 1
            assert calls[0].url == "/api/data"

    def test_scan_frontend_calls_skips_external(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("fetch('https://api.example.com/data')")
            calls = scan_frontend_calls(root)
            assert len(calls) == 0

    def test_findings_from_orphaned_endpoints(self):
        from patchi.core.brain.route_mapper import RouteInfo

        result = OrphanedEndpointResult(
            orphaned_routes=[
                RouteInfo(
                    method="GET",
                    path="/api/old-endpoint",
                    handler="old_handler",
                    file="routes.py",
                    line=10,
                    framework="FastAPI",
                ),
            ],
            dead_calls=[
                FrontendCall(url="/api/nonexistent", file="app.js", line=5, raw="fetch('/api/nonexistent')"),
            ],
            total_backend_routes=5,
            total_frontend_calls=3,
        )
        findings = findings_from_orphaned_endpoints(result)
        assert len(findings) == 2
        assert findings[0].type == "orphaned_backend_route"
        assert findings[1].type == "dead_frontend_call"


# ── Test Git Blame Integration ──────────────────────────────────────────────


class TestBlameIntegration:
    def test_annotate_findings_blame_not_in_git_repo(self):
        from patchi.core.brain.git_aware import annotate_findings_with_blame

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = [
                Finding(agent="test", type="err", severity=Severity.HIGH, file="a.py", line=1, message="bad"),
            ]
            count = annotate_findings_with_blame(findings, root)
            # No git repo, so 0 annotated
            assert count == 0


# ── Test Trend Metrics ──────────────────────────────────────────────────────


class TestTrendMetrics:
    def test_record_and_query_history(self):
        from patchi.core.security.history import (
            patchi_get_analytics,
            patchi_get_history,
            patchi_get_severity_trends,
            patchi_record_scan,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = [
                {"type": "err", "severity": "high", "file": "a.py", "line": 1},
                {"type": "warn", "severity": "medium", "file": "b.py", "line": 5},
            ]
            scan_id = patchi_record_scan(
                root=root,
                tool="test",
                findings=findings,
                duration_ms=100,
                health_score=85,
                metrics={"coverage": 72.5, "bundle_size": 420},
                agent_group="security",
            )
            assert scan_id is not None
            assert len(scan_id) == 12

            history = patchi_get_history(root, limit=5)
            assert len(history) == 1
            assert history[0]["findings_count"] == 2
            assert history[0]["health_score"] == 85

            analytics = patchi_get_analytics(root)
            assert analytics["total_scans"] == 1
            assert analytics["avg_findings_per_scan"] == 2.0

            trends = patchi_get_severity_trends(root, days=365)
            assert "labels" in trends
            assert "datasets" in trends

    def test_metrics_history(self):
        from patchi.core.security.history import patchi_get_metrics_history, patchi_record_scan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patchi_record_scan(
                root=root,
                tool="test",
                findings=[],
                metrics={"coverage": 80.0},
            )
            result = patchi_get_metrics_history(root, "coverage", days=365)
            assert len(result["values"]) == 1
            assert result["values"][0] == 80.0

    def test_health_scores(self):
        from patchi.core.security.history import patchi_get_health_scores, patchi_record_scan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            patchi_record_scan(root=root, tool="test", findings=[], health_score=90)
            result = patchi_get_health_scores(root, days=365)
            assert len(result["scores"]) == 1
            assert result["scores"][0] == 90


class TestFlakeDetectorAgent:
    """Tests for FlakeDetectorAgent (§6.1.4)."""

    def test_record_and_detect_flaky(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                {"name": "test_a", "passed": True, "duration_ms": 10},
                {"name": "test_b", "passed": True, "duration_ms": 20},
            ]
            record_test_run(root, "pytest", cases, 2, 2, 0, 0, 100)
            flakes = _detect_flaky_tests(root, min_runs=2)
            assert len(flakes) == 0, "No flakes yet with only 1 run"

            cases2 = [
                {"name": "test_a", "passed": False, "duration_ms": 10},
                {"name": "test_b", "passed": True, "duration_ms": 20},
            ]
            record_test_run(root, "pytest", cases2, 2, 1, 1, 0, 100)
            flakes = _detect_flaky_tests(root, min_runs=2)
            assert len(flakes) == 1
            assert flakes[0]["test_name"] == "test_a"
            assert flakes[0]["pass_count"] == 1
            assert flakes[0]["fail_count"] == 1

    def test_no_false_positive_stable_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                {"name": "test_ok", "passed": True, "duration_ms": 10},
            ]
            for _ in range(3):
                record_test_run(root, "pytest", cases, 1, 1, 0, 0, 50)
            flakes = _detect_flaky_tests(root, min_runs=2)
            assert len(flakes) == 0

    def test_detect_duration_outlier(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                {"name": "test_a", "passed": True, "duration_ms": 100},
            ]
            for dur in [100] * 10 + [5000]:
                cases[0]["duration_ms"] = dur
                record_test_run(root, "pytest", cases, 1, 1, 0, 0, dur)
            outliers = _detect_duration_outliers(root, z_threshold=3.0)
            assert len(outliers) == 1
            assert outliers[0]["test_name"] == "test_a"

    @patch("patchi.core.testing.gate.require_ready", return_value=(True, "http://fake", "READY_TO_SERVE"))
    def test_agent_returns_result(self, _mock_gate):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                {"name": "test_a", "passed": True, "duration_ms": 10},
                {"name": "test_b", "passed": False, "duration_ms": 20},
            ]
            record_test_run(root, "pytest", cases, 2, 1, 1, 0, 100)
            record_test_run(root, "pytest", cases, 2, 1, 1, 0, 100)

            agent = FlakeDetectorAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = agent.run(inp)
            assert result.agent_name == "FlakeDetectorAgent"
            assert result.data["total_runs"] == 2
            assert isinstance(result.data["flaky_tests"], int)
            assert isinstance(result.data["duration_outliers"], int)


# ── Test DeadCodeHygieneAgent (§2 A) ─────────────────────────────────────────


class TestDeadCodeHygieneAgent:
    def test_feature_flag_detection(self):
        content = "const showFeature = true\nconst isEnabled = false\n"
        flags = _find_feature_flags(content)
        assert len(flags) == 2

    def test_duplicate_deps_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package.json"
            pkg.write_text(json.dumps({
                "dependencies": {"lodash": "^4.0.0"},
                "devDependencies": {"lodash": "^4.17.0"},
            }))
            dups = _detect_duplicate_deps(root)
            assert len(dups) >= 1
            assert dups[0]["name"] == "lodash"

    def test_agent_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "app.py"
            src.write_text("x = True\n")
            agent = DeadCodeHygieneAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = agent.run(inp)
            assert result.agent_name == "DeadCodeHygieneAgent"
            assert "total_feature_flags" in result.data


# ── Dead code removal parity (Phase 7a) ──────────────────────────────────────


class TestDeadCodeParity:
    def test_scanner_finds_multilang_orphan_and_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.py").write_text("import used\nprint(used.hello())\n")
            (root / "used.py").write_text("def hello():\n    return 1\n")
            (root / "dead.py").write_text("def lonely():\n    return 2\n")
            (root / "app.js").write_text(
                'import { live } from "./live.js";\nconsole.log(live());\n'
            )
            (root / "live.js").write_text("export function live() { return 1; }\n")
            (root / "orphan.js").write_text(
                "function orphanFn() { return 2; }\nconst ORPHAN_C = 9;\n"
            )
            agent = DeadCodeScanner()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            res = AgentResult(agent_name="DeadCodeScanner")
            agent._run(inp, res)

            types = {(f.file, f.type) for f in res.findings}
            # file-level dead detection is language-agnostic
            assert ("dead.py", "uncertain_dead") in types
            assert ("orphan.js", "uncertain_dead") in types
            # intra-file dead symbols reported across languages
            dead_symbols = {
                f.file for f in res.findings if f.type == "dead_code"
            }
            assert "dead.py" in dead_symbols
            assert "orphan.js" in dead_symbols
            # imported / exported files must NOT be flagged dead
            assert ("used.py", "uncertain_dead") not in types
            assert ("live.js", "uncertain_dead") not in types

    def test_remover_skips_cross_language_dynamic_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "utils.py").write_text("def helper():\n    return 1\n")
            (root / "caller.js").write_text('const x = require("./utils");\n')
            findings = [
                {
                    "type": "confirmed_dead",
                    "fix_agent": "DeadCodeRemover",
                    "file": "utils.py",
                    "message": "x",
                }
            ]
            inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={"findings": findings})
            res = AgentResult(agent_name="DeadCodeRemover")
            DeadCodeRemover()._run(inp, res)
            # must be skipped because referenced from caller.js (non-Python, non-config)
            skipped = {s["file"] for s in res.data.get("skipped", [])}
            assert "utils.py" in skipped


# ── Test CICDGeneratorAgent (§10 B) ──────────────────────────────────────────


class TestCICDGeneratorAgent:
    def test_generates_missing_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = CICDGeneratorAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = agent.run(inp)
            assert result.agent_name == "CICDGeneratorAgent"
            assert len(result.data["generated"]) == 3
            assert ".pre-commit-config.yaml" in result.data["generated"]
            assert len(result.findings) >= 3

    def test_detects_existing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".pre-commit-config.yaml").write_text("repos: []")
            gh = root / ".github" / "workflows"
            gh.mkdir(parents=True)
            (gh / "patchi-ci.yml").write_text("name: CI")
            (root / ".gitlab-ci.yml").write_text("stages: []")
            agent = CICDGeneratorAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = agent.run(inp)
            assert len(result.data["generated"]) == 0


# ── Test RefactoringAgent (§7 C) ─────────────────────────────────────────────


class TestRefactoringAgent:
    def test_interval_leak_detection(self):
        content = "const id = setInterval(() => {}, 1000);\n"
        findings = _detect_interval_without_cleanup(content, "javascript")
        assert len(findings) == 1
        assert findings[0]["type"] == "setInterval"

    def test_file_handle_leak(self):
        content = "fs.createReadStream('/tmp/file');\n"
        findings = _detect_file_handle_leaks(content, "javascript")
        assert len(findings) == 1

    def test_modernization_candidates(self):
        content = "var x = 1;\n"
        findings = _detect_modernization_candidates(content, ".js", "javascript")
        assert len(findings) >= 1
        assert findings[0]["type"] == "var_to_const_let"

    def test_agent_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "app.js"
            src.write_text("const id = setInterval(() => {}, 1000);\nuseEffect(() => {});\n")
            agent = RefactoringAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = agent.run(inp)
            assert result.agent_name == "RefactoringAgent"
            assert isinstance(result.data.get("interval_leaks"), list)


# ── Test SBOMGeneratorAgent (§11.5 D) ────────────────────────────────────────


class TestSBOMGeneratorAgent:
    def test_sbom_from_package_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package.json"
            pkg.write_text(json.dumps({
                "dependencies": {"express": "^4.18.0", "lodash": "^4.17.0"},
                "devDependencies": {"jest": "^29.0.0"},
            }))
            agent = SBOMGeneratorAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = agent.run(inp)
            assert result.agent_name == "SBOMGeneratorAgent"
            assert result.data.get("total_components", 0) == 3

    def test_sbom_from_requirements_txt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            req = root / "requirements.txt"
            req.write_text("flask==2.3.0\nrequests>=2.28.0\n")
            agent = SBOMGeneratorAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = agent.run(inp)
            assert result.data.get("total_components", 0) == 2

    def test_sbom_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package.json"
            pkg.write_text(json.dumps({"dependencies": {"react": "^18.0.0"}}))
            agent = SBOMGeneratorAgent()
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            agent.run(inp)
            sbom_path = root / ".patchi" / "sbom.cdx.json"
            assert sbom_path.exists()
            data = json.loads(sbom_path.read_text())
            assert data["bomFormat"] == "CycloneDX"


# ── Test SPARouteInventoryAgent (§3.3.1) ────────────────────────────────────


class TestSPARouteInventoryAgent:
    def test_detects_react_router(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "app.jsx"
            src.write_text("const router = createBrowserRouter([{ path: '/home' }, { path: '/about' }]);")
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = SPARouteInventoryAgent().run(inp)
            assert result.data.get("total_routes", 0) >= 1

    def test_detects_dead_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "app.jsx"
            src.write_text("createBrowserRouter([{ path: '/home' }]);\n")
            page = root / "page.jsx"
            page.write_text('<Link to="/home"><Link to="/dead-page">')
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = SPARouteInventoryAgent().run(inp)
            dead = [f for f in result.findings if f.type == "dead_link"]
            assert any("/dead-page" in f.message for f in dead)


# ── Test CoveragePrioritizerAgent (§6.1.1) ──────────────────────────────────


class TestCoveragePrioritizerAgent:
    def test_agent_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "file.py").write_text("x=1")
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = CoveragePrioritizerAgent().run(inp)
            assert result.agent_name == "CoveragePrioritizerAgent"


# ── Test BuildToolValidatorAgent (§8.3.1) ────────────────────────────────────


class TestBuildToolValidatorAgent:
    def test_detects_vite_missing_optimize(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "vite.config.ts"
            cfg.write_text("import { defineConfig } from 'vite';\nexport default defineConfig({})")
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = BuildToolValidatorAgent().run(inp)
            issues = [f for f in result.findings if f.type == "build_config_issue"]
            assert any("optimizeDeps" in f.message for f in issues)

    def test_webpack_no_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = root / "webpack.config.js"
            cfg.write_text("module.exports = { entry: './src/index.js' };")
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = BuildToolValidatorAgent().run(inp)
            issues = [f for f in result.findings if f.type == "build_config_issue"]
            assert any("mode" in f.message for f in issues)


# ── Test LicenseComplianceAgent (§11.6) ──────────────────────────────────────


class TestLicenseComplianceAgent:
    def test_detects_restricted_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package.json"
            pkg.write_text(json.dumps({
                "license": "GPL-3.0",
                "dependencies": {"some-gpl-lib": "^1.0.0"},
            }))
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = LicenseComplianceAgent().run(inp)
            restricted = [f for f in result.findings if f.type == "restricted_license"]
            assert len(restricted) >= 1

    def test_allows_mit_license(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package.json"
            pkg.write_text(json.dumps({
                "license": "MIT",
                "dependencies": {"safe-lib": "^1.0.0"},
            }))
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = LicenseComplianceAgent().run(inp)
            restricted = [f for f in result.findings if f.type == "restricted_license"]
            assert len(restricted) == 0


# ── Test SnapshotDriftDetectorAgent (§6.2.1) ────────────────────────────────


class TestSnapshotDriftDetectorAgent:
    def test_detects_snapshot_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snap_dir = root / "__snapshots__"
            snap_dir.mkdir()
            snap = snap_dir / "test.snap"
            snap.write_text("// Jest Snapshot v1\n\nexports[test] = `<div>old</div>`;")

            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result1 = SnapshotDriftDetectorAgent().run(inp)
            assert result1.data["total_drifts"] == 0

            snap.write_text("// Jest Snapshot v1\n\nexports[test] = `<div>new</div>`;")
            result2 = SnapshotDriftDetectorAgent().run(inp)
            assert result2.data["total_drifts"] == 1

    def test_no_snapshots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inp = AgentInput(root=root, scope=[], brain={}, config={})
            result = SnapshotDriftDetectorAgent().run(inp)
            no_snap = [f for f in result.findings if f.type == "no_snapshots"]
            assert len(no_snap) == 1


# ── TaintAnalyzer AST conversion (Phase 6j) ──────────────────────────────────


class TestTaintAnalyzerPhase6j:
    def _run(self, root: Path):
        agent = TaintAnalyzer()
        agent._confirm_with_ai = lambda *a, **k: None  # no AI backend in tests
        inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={})
        res = AgentResult(agent_name=agent.name, agent_group=agent.group, status=AgentStatus.RUNNING)
        agent._run(inp, res)
        return res

    def test_ast_detects_command_and_code_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "from flask import request\n"
                "import os\n"
                "user = request.args.get('q')\n"
                "os.system('echo ' + user)\n"
                "eval(user)\n"
            )
            res = self._run(root)
            types = {f.type for f in res.findings}
            assert "taint_command_injection" in types
            assert "taint_code_injection" in types

    def test_multilang_scan_support(self):
        # TaintAnalyzer now scans every parser-supported language, not just 4.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.go").write_text(
                'package main\n'
                'import "os"\n'
                'func main() {\n'
                '  os.Getenv("INPUT")\n'
                '  exec.Command("sh", "-c", input)\n'
                '}\n'
            )
            res = self._run(root)
            # at minimum the file is scanned (no crash) and AST taint attempted
            assert res.files_scanned >= 1


# ── Fix agent parity (Phase 7b) ──────────────────────────────────────────────


class TestFixAgentsParity:
    def test_code_fixer_passes_language(self):
        from patchi.core.fix import code_fixer

        captured = {}
        with mock.patch.object(code_fixer, "_call_ai", lambda prompt, cfg, **kwargs: captured.setdefault("p", prompt) or "```\nprint('x')\n```"):
            agent = CodeFixer()
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "app.go").write_text("package main\nfunc main(){}\n")
                f = Finding("CodeFixer", "bug", Severity.LOW, "app.go", line=2, message="m", fix_agent="CodeFixer")
                inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={"findings": [f.to_dict()]})
                res = AgentResult(agent_name=agent.name, agent_group=agent.group, status=AgentStatus.RUNNING)
                agent._run(inp, res)
                assert res.data.get("patch_count", 0) == 1
                assert "Language: go" in captured["p"]

    def test_type_fixer_multilang_types(self):
        from patchi.core.fix import fix_agents

        types = ["explicit_any", "unsafe_cast", "ts_ignore", "missing_return_type",
                 "missing_param_type", "untyped_return", "any_type", "non_null_assertion",
                 "missing_type", "dynamic_type"]
        with mock.patch.object(fix_agents, "_ai_fix", lambda *a, **k: "```\npackage main\n```"):
            agent = TypeFixer()
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "svc.go").write_text("package main\n")
                findings = [
                    Finding("TypeScanner", t, Severity.MEDIUM, "svc.go", line=1, message=t).to_dict()
                    for t in types
                ]
                inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={"findings": findings})
                res = AgentResult(agent_name=agent.name, agent_group=agent.group, status=AgentStatus.RUNNING)
                agent._run(inp, res)
                # cap is 10 per run; all 10 distinct non-TS types must be handled
                assert res.data.get("patch_count", 0) == 10
                handled = {p["finding_id"] for p in res.data.get("patches", [])}
                assert "any_type" in handled  # Kotlin/Swift type issue
                assert "missing_type" in handled  # Python type issue
                assert "dynamic_type" in handled  # Dart type issue

    def test_type_fixer_ignores_non_type_findings(self):
        from patchi.core.fix import fix_agents

        with mock.patch.object(fix_agents, "_ai_fix", lambda *a, **k: "```\nx\n```"):
            agent = TypeFixer()
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "svc.go").write_text("package main\n")
                # a non-type finding must NOT be fixed by TypeFixer
                findings = [
                    Finding("SomeScanner", "hardcoded_secret", Severity.HIGH, "svc.go", line=1, message="s").to_dict()
                ]
                inp = AgentInput(root=root, scope=[], brain={}, config={}, extra={"findings": findings})
                res = AgentResult(agent_name=agent.name, agent_group=agent.group, status=AgentStatus.RUNNING)
                agent._run(inp, res)
                assert res.data.get("patch_count", 0) == 0

    def test_detect_language_coverage(self):
        assert _detect_language("a.py") == "python"
        assert _detect_language("a.ts") == "typescript"
        assert _detect_language("a.go") == "go"
        assert _detect_language("a.rs") == "rust"
        assert _detect_language("a.java") == "java"

