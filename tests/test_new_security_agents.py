"""Tests for new security agents: orchestrator, secrets guard, supply chain, IaC, policy, CVE monitor, red team, security test agent."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from patchi.core.agents.base import (
    AgentInput,
    AgentResult,
    AgentStatus,
    Finding,
    Severity,
)
from patchi.core.security.cve_monitor import CVEMonitorAgent
from patchi.core.security.iac_scanner import IaCScannerAgent
from patchi.core.security.orchestrator import (
    SecurityOrchestrator,
)
from patchi.core.security.policy_engine import PolicyEngineAgent, _check_policy
from patchi.core.security.red_team_agent import RedTeamAgent
from patchi.core.security.secrets_runtime_agent import (
    SecretsRuntimeAgent,
    gate_check_proposed_code,
    scan_code_for_secrets,
)
from patchi.core.security.supply_chain import SupplyChainAgent, _is_likely_typosquat, _levenshtein
from patchi.core.testing.security_test_agent import SecurityTestAgent


def _inp(root: Path) -> AgentInput:
    return AgentInput(root=root, scope=[], brain={}, config={}, extra={})


def _write(root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


# ── Orchestrator ──────────────────────────────────────────────────────────────


class TestOrchestrator(unittest.TestCase):
    @pytest.mark.integration
    def test_deduplication(self):
        orch = SecurityOrchestrator()
        f1 = Finding(
            agent="A",
            type="sql_injection",
            severity=Severity.HIGH,
            file="x.py",
            line=10,
            cwe="CWE-89",
        )
        f2 = Finding(
            agent="B",
            type="sql_injection",
            severity=Severity.HIGH,
            file="x.py",
            line=10,
            cwe="CWE-89",
        )
        r1 = AgentResult(agent_name="A", findings=[f1])
        r2 = AgentResult(agent_name="B", findings=[f2])
        report = orch.correlate([r1, r2])
        self.assertEqual(report.total_findings, 1)
        self.assertEqual(report.correlation_count, 1)
        self.assertIn("A", report.findings[0].confirmed_by)
        self.assertIn("B", report.findings[0].confirmed_by)

    def test_severity_ordering(self):
        orch = SecurityOrchestrator()
        f_low = Finding(agent="A", type="info", severity=Severity.LOW, file="a.py", line=1)
        f_crit = Finding(agent="B", type="vuln", severity=Severity.CRITICAL, file="b.py", line=2)
        r1 = AgentResult(agent_name="A", findings=[f_low])
        r2 = AgentResult(agent_name="B", findings=[f_crit])
        report = orch.correlate([r1, r2])
        self.assertEqual(report.findings[0].finding.severity, Severity.CRITICAL)

    def test_owasp_classification(self):
        orch = SecurityOrchestrator()
        f = Finding(
            agent="A", type="sql_injection", severity=Severity.HIGH, file="x.py", cwe="CWE-89"
        )
        r = AgentResult(agent_name="A", findings=[f])
        report = orch.correlate([r])
        self.assertIn("Injection", report.findings[0].owasp_category)


# ── Secrets Guard ─────────────────────────────────────────────────────────────


class TestSecretsRuntimeAgent(unittest.TestCase):
    def test_detects_api_key(self):
        # Part 7: the AWS docs example key is a placeholder — use a realistic one.
        code = 'api_key = "AKIAIOSFODNN7XKQ9MWB2DT8FV4HJ6"\n'
        findings = scan_code_for_secrets(code, "test.py")
        self.assertTrue(any("AWS" in f["message"] for f in findings))

    def test_docs_example_key_rejected(self):
        code = 'api_key = "AKIAIOSFODNN7EXAMPLE"\n'
        findings = scan_code_for_secrets(code, "test.py")
        self.assertEqual(findings, [])

    def test_detects_password(self):
        # Part 7: hunter2 is too weak to verify — use a secret-shaped value.
        code = 'password = "9f8eD2xQ7vB4mK1wZ6"\n'
        findings = scan_code_for_secrets(code, "test.py")
        self.assertTrue(any("password" in f["message"].lower() for f in findings))

    def test_weak_password_rejected(self):
        code = 'password = "hunter2"\n'
        findings = scan_code_for_secrets(code, "test.py")
        self.assertEqual(findings, [])

    def test_clean_code_passes(self):
        code = 'name = "hello"\n'
        findings = scan_code_for_secrets(code, "test.py")
        self.assertEqual(len(findings), 0)

    def test_gate_blocks_secret(self):
        # Part 7: sequential "ABCDEF..." runs are fake-shaped — use a realistic value.
        safe, findings = gate_check_proposed_code('api_key = "Q7ZmK2vX9pL4wN8cR3tY6uI1oP5aS0"\n', "x.py")
        self.assertFalse(safe)
        self.assertTrue(len(findings) > 0)

    def test_gate_allows_clean(self):
        safe, findings = gate_check_proposed_code('name = "hello"\n', "x.py")
        self.assertTrue(safe)

    def test_runs_on_empty_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            result = SecretsRuntimeAgent().run(_inp(r))
            self.assertEqual(result.status, AgentStatus.DONE)


# ── Supply Chain ──────────────────────────────────────────────────────────────


class TestSupplyChain(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(_levenshtein("kitten", "sitting"), 3)
        self.assertEqual(_levenshtein("abc", "abc"), 0)

    def test_typosquat_detection(self):
        is_squat, target = _is_likely_typosquat("numpi")
        self.assertTrue(is_squat)
        self.assertEqual(target, "numpy")

    def test_no_false_positive_on_real_package(self):
        is_squat, _ = _is_likely_typosquat("requests")
        self.assertFalse(is_squat)

    def test_runs_on_empty_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            result = SupplyChainAgent().run(_inp(r))
            self.assertEqual(result.status, AgentStatus.DONE)


# ── IaC Scanner ──────────────────────────────────────────────────────────────


class TestIaCScanner(unittest.TestCase):
    def test_detects_root_user(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            _write(r, "Dockerfile", "FROM ubuntu\nRUN apt-get update\nUSER root\n")
            result = IaCScannerAgent().run(_inp(r))
            self.assertTrue(any("root" in f.message for f in result.findings))

    def test_detects_latest_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            _write(r, "Dockerfile", "FROM ubuntu:latest\n")
            result = IaCScannerAgent().run(_inp(r))
            self.assertTrue(any("latest" in f.message.lower() for f in result.findings))

    def test_detects_privileged(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            _write(r, "docker-compose.yml", "services:\n  app:\n    privileged: true\n")
            result = IaCScannerAgent().run(_inp(r))
            self.assertTrue(any("privileged" in f.message.lower() for f in result.findings))

    def test_detects_public_s3(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            _write(r, "s3.tf", 'resource "aws_s3_bucket" "b" {\n  acl = "public"\n}\n')
            result = IaCScannerAgent().run(_inp(r))
            self.assertTrue(any("public" in f.message.lower() for f in result.findings))


# ── Policy Engine ─────────────────────────────────────────────────────────────


class TestPolicyEngine(unittest.TestCase):
    def test_check_default_credentials(self):
        violations = _check_policy("no_default_credentials", 'password = "admin"', [])
        self.assertTrue(len(violations) > 0)

    def test_check_weak_crypto(self):
        violations = _check_policy("no_weak_crypto", "import hashlib\nhashlib.md5(data)", [])
        self.assertTrue(len(violations) > 0)

    def test_check_clean_code(self):
        violations = _check_policy("no_default_credentials", 'name = "hello"', [])
        self.assertEqual(len(violations), 0)

    def test_runs_on_empty_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            result = PolicyEngineAgent().run(_inp(r))
            self.assertEqual(result.status, AgentStatus.DONE)


# ── CVE Monitor ───────────────────────────────────────────────────────────────


class TestCVEMonitor(unittest.TestCase):
    def test_runs_on_empty_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            result = CVEMonitorAgent().run(_inp(r))
            self.assertEqual(result.status, AgentStatus.DONE)


# ── Red Team ──────────────────────────────────────────────────────────────────


class TestRedTeam(unittest.TestCase):
    def setUp(self):
        self._gate_patcher = patch(
            "patchi.core.testing.gate.require_ready",
            return_value=(True, "http://fake", "READY_TO_SERVE"),
        )
        self._gate_patcher.start()

    def tearDown(self):
        self._gate_patcher.stop()

    def test_detects_eval(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            _write(r, "app.py", "result = eval(user_input)\n")
            result = RedTeamAgent().run(_inp(r))
            self.assertTrue(any("eval" in f.message.lower() for f in result.findings))

    def test_detects_debug_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            _write(r, "settings.py", "DEBUG = True\n")
            result = RedTeamAgent().run(_inp(r))
            self.assertTrue(any("debug" in f.message.lower() for f in result.findings))

    def test_runs_on_empty_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            result = RedTeamAgent().run(_inp(r))
            self.assertEqual(result.status, AgentStatus.DONE)


# ── Security Test Agent ──────────────────────────────────────────────────────


class TestSecurityTestAgent(unittest.TestCase):
    def setUp(self):
        self._gate_patcher = patch(
            "patchi.core.testing.gate.require_ready",
            return_value=(True, "http://fake", "READY_TO_SERVE"),
        )
        self._gate_patcher.start()

    def tearDown(self):
        self._gate_patcher.stop()

    def test_generates_tests_for_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            brain = {"routes": [{"path": "/api/users", "method": "get"}]}
            inp = AgentInput(root=r, scope=[], brain=brain, config={}, extra={})
            result = SecurityTestAgent().run(inp)
            self.assertTrue(result.files_scanned > 0)

    def test_no_routes_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp)
            result = SecurityTestAgent().run(_inp(r))
            self.assertEqual(result.status, AgentStatus.DONE)
            self.assertEqual(result.files_scanned, 0)


if __name__ == "__main__":
    unittest.main()
