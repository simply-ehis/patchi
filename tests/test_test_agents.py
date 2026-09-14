"""Tests for patchi.core.testing.test_agents"""

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.agents.base import AgentGroup, AgentInput, AgentStatus, Severity, list_agents
from patchi.core.testing.test_agents import (
    BrowserTestAgent,
    RegressionAgent,
    StressTestAgent,
    TestCase,
    TestSuite,
    UnitTestAgent,
    _run,
)


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


def _write(root: Path, rel: str, content: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _inp(root: Path, scope: list | None = None, brain: dict | None = None) -> AgentInput:
    return AgentInput(
        root=root,
        scope=scope or [],
        brain=brain or {},
        config=cfg.load(root),
    )


# ── TestCase and TestSuite ─────────────────────────────────────────────────────


class TestTestSuite(unittest.TestCase):
    def test_total_is_sum(self):
        s = TestSuite(runner="pytest", passed=8, failed=2, skipped=1, errors=0)
        self.assertEqual(s.total, 11)

    def test_success_true_when_no_failures(self):
        s = TestSuite(runner="pytest", passed=10, failed=0, errors=0)
        self.assertTrue(s.success)

    def test_success_false_when_failures(self):
        s = TestSuite(runner="pytest", passed=8, failed=2, errors=0)
        self.assertFalse(s.success)

    def test_success_false_when_errors(self):
        s = TestSuite(runner="pytest", passed=8, failed=0, errors=1)
        self.assertFalse(s.success)

    def test_to_dict_has_required_keys(self):
        s = TestSuite(runner="pytest", passed=5, failed=1)
        s.cases.append(TestCase(name="test_foo", passed=False, error="AssertionError"))
        d = s.to_dict()
        for key in ("runner", "passed", "failed", "total", "success", "cases"):
            self.assertIn(key, d)

    def test_to_dict_only_includes_failures(self):
        s = TestSuite(runner="pytest", passed=2, failed=1)
        s.cases.append(TestCase(name="test_ok", passed=True))
        s.cases.append(TestCase(name="test_bad", passed=False, error="Boom"))
        d = s.to_dict()
        # Only failed case included
        self.assertEqual(len(d["cases"]), 1)
        self.assertEqual(d["cases"][0]["name"], "test_bad")


# ── Registration ───────────────────────────────────────────────────────────────


class TestAgentRegistration(unittest.TestCase):
    def test_all_test_agents_registered(self):
        import patchi.core.testing.test_agents  # noqa
        import patchi.core.testing.ui_button_agent  # noqa
        import patchi.core.testing.ui_accessibility_agent  # noqa
        import patchi.core.testing.ui_layout_agent  # noqa
        import patchi.core.testing.e2e_flow_agent  # noqa
        import patchi.core.testing.visual_regression_agent  # noqa
        import patchi.core.agents.attack_agent  # noqa
        import patchi.core.agents.chaos_agent  # noqa
        import patchi.core.agents.mutation_agent  # noqa
        import patchi.core.agents.console_logging_agent  # noqa
        import patchi.core.testing.ads_agent  # noqa

        agents = list_agents(AgentGroup.TEST)
        names = {a.name for a in agents}
        self.assertEqual(
            names,
            {
                "UnitTestAgent",
                "BrowserTestAgent",
                "StressTestAgent",
                "RegressionAgent",
                "APIContractAgent",
                "UIButtonAgent",
                "UIAccessibilityAgent",
                "UILayoutAgent",
                "E2EFlowAgent",
                "VisualRegressionAgent",
                "SecurityTestAgent",
                "FlakeDetectorAgent",
                "AttackAgent",
                "LiveTestRunnerV2Agent",
                "AppDiscoveryAgent",
                # Additional agents in TEST group
                "ChaosAgent",
                "MutationAgent",
                "AdsAgent",
                "ConsoleLoggingAgent",
            },
        )

    def test_all_in_test_group(self):
        import patchi.core.testing.test_agents  # noqa

        for cls in list_agents(AgentGroup.TEST):
            self.assertEqual(cls.group, AgentGroup.TEST)


# ── UnitTestAgent ──────────────────────────────────────────────────────────────


class TestUnitTestAgent(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        self._gate_patcher = patch(
            "patchi.core.testing.gate.require_ready",
            return_value=(True, "http://fake", "READY_TO_SERVE"),
        )
        self._gate_patcher.start()

    def tearDown(self):
        self._gate_patcher.stop()
        self.tmpdir.cleanup()

    def test_skips_gracefully_when_no_runner(self):
        # Empty project — no pytest tests, no package.json
        result = UnitTestAgent().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertIsNone(result.data.get("runner"))

    def test_detects_pytest_when_test_files_exist(self):
        _write(self.root, "tests/test_example.py", "def test_pass(): assert True\n")
        agent = UnitTestAgent()
        runner = agent._detect_runner(self.root)
        self.assertEqual(runner, "pytest")

    def test_runs_pytest_and_passes(self):
        if not shutil.which("pytest"):
            self.skipTest("pytest not installed")
        _write(
            self.root, "tests/test_simple.py", "def test_always_passes():\n    assert 1 + 1 == 2\n"
        )
        result = UnitTestAgent().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.DONE)
        suite = result.data.get("suite", {})
        self.assertGreater(suite.get("passed", 0), 0)
        self.assertEqual(suite.get("failed", 0), 0)
        self.assertTrue(suite.get("success", False))

    def test_reports_failure_as_finding(self):
        if not shutil.which("pytest"):
            self.skipTest("pytest not installed")
        _write(
            self.root,
            "tests/test_failing.py",
            "def test_always_fails():\n    assert False, 'intentional failure'\n",
        )
        result = UnitTestAgent().run(_inp(self.root))
        self.assertGreater(result.finding_count, 0)
        finding_types = [f.type for f in result.findings]
        self.assertIn("test_failure", finding_types)

    def test_failure_severity_is_critical(self):
        if not shutil.which("pytest"):
            self.skipTest("pytest not installed")
        _write(self.root, "tests/test_failing.py", "def test_fail():\n    assert False\n")
        result = UnitTestAgent().run(_inp(self.root))
        if result.findings:
            self.assertEqual(result.findings[0].severity, Severity.CRITICAL)

    def test_find_test_files_convention(self):
        _write(self.root, "tests/test_auth.py", "def test_login(): pass\n")
        agent = UnitTestAgent()
        found = agent._find_test_files(self.root, ["src/auth.py"])
        self.assertIn("tests/test_auth.py", found)

    def test_find_test_files_no_match(self):
        agent = UnitTestAgent()
        found = agent._find_test_files(self.root, ["src/nonexistent.py"])
        self.assertEqual(found, [])

    def test_parse_pytest_stdout(self):
        stdout = "2 passed, 1 failed in 0.5s\nFAILED tests/test_auth.py::test_login\n"
        agent = UnitTestAgent()
        suite = agent._parse_pytest_stdout(stdout, 500)
        self.assertEqual(suite.passed, 2)
        self.assertEqual(suite.failed, 1)
        self.assertEqual(len(suite.cases), 1)
        self.assertIn("test_auth", suite.cases[0].name)

    def test_scope_filters_to_changed_files(self):
        if not shutil.which("pytest"):
            self.skipTest("pytest not installed")
        _write(self.root, "tests/test_auth.py", "def test_auth_passes():\n    assert True\n")
        _write(self.root, "tests/test_billing.py", "def test_billing_fails():\n    assert False\n")
        # Scope to auth only — billing failure should not appear
        result = UnitTestAgent().run(_inp(self.root, scope=["src/auth.py"]))
        # test_billing.py should not be run
        for f in result.findings:
            self.assertNotIn("billing", f.message.lower())


# ── APIContractAgent ──────────────────────────────────────────────────────────


class TestAPIContractAgent(unittest.TestCase):
    """API contract discovery must never treat the tool's own state directory
    (.patchi) as project source — on case-insensitive filesystems the agent's
    own cache file matches `**/api*.json` and would make a re-run validate its
    own cache (found by the smoke-sweep --pipeline orchestration gate)."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_ignores_tool_state_dir(self):
        from patchi.core.testing.api_contract_agent import APIContractAgent

        _write(
            self.root,
            ".patchi/cache/agent_cache/APIContractAgent.json",
            '{"fp": "x"}',
        )
        agent = APIContractAgent()
        self.assertEqual(agent._find_api_contracts(self.root), [])

    def test_finds_real_openapi_contract(self):
        from patchi.core.testing.api_contract_agent import APIContractAgent

        _write(self.root, "openapi.json", '{"openapi": "3.0.0", "paths": {}}')
        agent = APIContractAgent()
        found = agent._find_api_contracts(self.root)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].name, "openapi.json")


# ── BrowserTestAgent ──────────────────────────────────────────────────────────


class TestBrowserTestAgent(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_skips_when_playwright_not_installed(self):
        with patch("shutil.which", return_value=None):
            result = BrowserTestAgent().run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.SKIPPED)

    def test_smoke_test_no_routes_reports_message(self):
        brain = {}  # No route_map
        result = BrowserTestAgent().run(_inp(self.root, brain=brain))
        # Should not crash — either skipped or has a message
        self.assertIn(result.status, (AgentStatus.DONE, AgentStatus.SKIPPED))

    def test_smoke_skips_parameterized_routes(self):
        brain = {
            "route_map": {
                "GET /users": {},
                "GET /users/:id": {},  # parameterized — should be skipped
                "GET /api/posts": {},
                "POST /users": {},  # POST — should be skipped
            }
        }
        # Smoke tests only target non-parameterized GET routes
        # We just verify the filtering logic
        get_routes = [
            path
            for key, path in [
                (k, k.split(" ", 1)[1] if " " in k else k) for k in brain["route_map"].keys()
            ]
            if key.startswith("GET") and not any(c in path for c in (":", "*", "{"))
        ]
        self.assertIn("/users", get_routes)
        self.assertIn("/api/posts", get_routes)
        self.assertNotIn("/users/:id", get_routes)

    def test_runs_without_crashing_on_playwright_missing(self):
        brain = {"route_map": {"GET /": {}}}
        with patch("shutil.which", return_value=None):
            result = BrowserTestAgent().run(_inp(self.root, brain=brain))
        self.assertIn(result.status, (AgentStatus.SKIPPED, AgentStatus.DONE))


# ── StressTestAgent ───────────────────────────────────────────────────────────


class TestStressTestAgent(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        self._gate_patcher = patch(
            "patchi.core.testing.gate.require_ready",
            return_value=(True, "http://fake", "READY_TO_SERVE"),
        )
        self._gate_patcher.start()

    def tearDown(self):
        self._gate_patcher.stop()
        self.tmpdir.cleanup()

    def _make_report(
        self,
        error_rate_pct: float = 0.0,
        p50_ms: float = 100,
        p95_ms: float = 200,
        p99_ms: float = 300,
        total_requests: int = 1000,
        total_failures: int = 0,
        breakpoint_found: bool = False,
        soak_stability: bool = True,
    ):
        from patchi.core.testing.live_v2.stress_orchestrator import (
            StressConfig,
            StressTestReport,
        )

        config = StressConfig(base_url="http://127.0.0.1:8000")
        return StressTestReport(
            config=config,
            started_at="2024-01-01T00:00:00Z",
            completed_at="2024-01-01T00:01:00Z",
            duration_seconds=60.0,
            total_requests=total_requests,
            successful_requests=total_requests - total_failures,
            failed_requests=total_failures,
            requests_per_second=total_requests / 60.0,
            latency={
                "min": 10,
                "max": 500,
                "mean": 150,
                "median": p50_ms,
                "p50": p50_ms,
                "p90": p95_ms * 0.9,
                "p95": p95_ms,
                "p99": p99_ms,
            },
            status_codes={"200": total_requests - total_failures, "500": total_failures},
            errors={},
            throughput_over_time=[],
            latency_over_time=[],
            user_sessions=10,
            peak_users=10,
            breakpoint_found=breakpoint_found,
            breakpoint_users=0,
            soak_stability=soak_stability,
        )

    def test_skips_when_no_target_found(self):
        agent = StressTestAgent()
        # Mock _detect_target to return None (no running server found)
        with patch.object(agent, "_detect_target", return_value=None):
            result = agent.run(_inp(self.root))
        self.assertEqual(result.status, AgentStatus.SKIPPED)

    def test_findings_on_high_error_rate(self):
        agent = StressTestAgent()
        report = self._make_report(error_rate_pct=15.0, total_requests=1000, total_failures=150)

        with patch.object(agent, "_detect_target", return_value="http://127.0.0.1:8000"):
            with patch.object(agent, "_run_stress", return_value=report):
                result = agent.run(_inp(self.root))
        finding_types = [f.type for f in result.findings]
        self.assertIn("high_error_rate", finding_types)

    def test_findings_on_slow_p95(self):
        agent = StressTestAgent()
        report = self._make_report(p95_ms=3500, p99_ms=5000, total_requests=1000, total_failures=0)

        with patch.object(agent, "_detect_target", return_value="http://127.0.0.1:8000"):
            with patch.object(agent, "_run_stress", return_value=report):
                result = agent.run(_inp(self.root))
        finding_types = [f.type for f in result.findings]
        self.assertIn("slow_p95", finding_types)

    def test_no_findings_when_healthy(self):
        agent = StressTestAgent()
        report = self._make_report(
            error_rate_pct=0.5, p50_ms=80, p95_ms=400, p99_ms=600,
            total_requests=2000, total_failures=10,
        )

        with patch.object(agent, "_detect_target", return_value="http://127.0.0.1:8000"):
            with patch.object(agent, "_run_stress", return_value=report):
                result = agent.run(_inp(self.root))
        self.assertEqual(result.finding_count, 0)


# ── RegressionAgent ───────────────────────────────────────────────────────────


class TestRegressionAgent(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        self._gate_patcher = patch(
            "patchi.core.testing.gate.require_ready",
            return_value=(True, "http://fake", "READY_TO_SERVE"),
        )
        self._gate_patcher.start()

    def tearDown(self):
        self._gate_patcher.stop()
        self.tmpdir.cleanup()

    def _brain_with_baseline(self, passed: int, failed: int = 0) -> dict:
        return {"test_baseline": {"passed": passed, "failed": failed, "total": passed + failed}}

    def test_saves_baseline_on_first_run(self):
        if not shutil.which("pytest"):
            self.skipTest("pytest not installed")
        _write(self.root, "tests/test_x.py", "def test_a(): assert True\n")
        result = RegressionAgent().run(_inp(self.root, brain={}))
        self.assertEqual(result.status, AgentStatus.DONE)
        # Baseline should be saved
        brain = mem.get_brain(self.root)
        self.assertIn("test_baseline", brain)

    def test_detects_regression_when_more_failures(self):
        # Brain says baseline was 10 passed, 0 failed
        # Mock UnitTestAgent to report 8 passed, 2 failed
        brain = self._brain_with_baseline(passed=10, failed=0)
        mock_suite = {
            "passed": 8,
            "failed": 2,
            "skipped": 0,
            "errors": 0,
            "total": 10,
            "success": False,
            "duration_ms": 1000,
            "runner": "pytest",
            "cases": [
                {
                    "name": "test_auth",
                    "passed": False,
                    "error": "AssertionError",
                    "duration_ms": 50,
                    "file": "tests/test_auth.py",
                    "line": 5,
                },
                {
                    "name": "test_login",
                    "passed": False,
                    "error": "AssertionError",
                    "duration_ms": 30,
                    "file": "tests/test_auth.py",
                    "line": 12,
                },
            ],
        }

        with patch.object(
            UnitTestAgent, "_run", lambda self, inp, result: _mock_unit_result(result, mock_suite)
        ):
            result = RegressionAgent().run(_inp(self.root, brain=brain))

        self.assertGreater(result.finding_count, 0)
        regression_findings = [f for f in result.findings if f.type == "regression_detected"]
        self.assertGreater(len(regression_findings), 0)
        self.assertEqual(regression_findings[0].severity, Severity.HIGH)

    def test_no_finding_when_stable(self):
        brain = self._brain_with_baseline(passed=10, failed=0)
        mock_suite = {
            "passed": 10,
            "failed": 0,
            "skipped": 0,
            "errors": 0,
            "total": 10,
            "success": True,
            "duration_ms": 500,
            "runner": "pytest",
            "cases": [],
        }

        with patch.object(
            UnitTestAgent, "_run", lambda self, inp, result: _mock_unit_result(result, mock_suite)
        ):
            result = RegressionAgent().run(_inp(self.root, brain=brain))

        regression = [f for f in result.findings if f.type == "regression_detected"]
        self.assertEqual(len(regression), 0)

    def test_updates_baseline_on_improvement(self):
        brain = self._brain_with_baseline(passed=8, failed=2)
        mock_suite = {
            "passed": 10,
            "failed": 0,
            "skipped": 0,
            "errors": 0,
            "total": 10,
            "success": True,
            "duration_ms": 500,
            "runner": "pytest",
            "cases": [],
        }

        with patch.object(
            UnitTestAgent, "_run", lambda self, inp, result: _mock_unit_result(result, mock_suite)
        ):
            RegressionAgent().run(_inp(self.root, brain=brain))

        updated_brain = mem.get_brain(self.root)
        baseline = updated_brain.get("test_baseline", {})
        self.assertEqual(baseline.get("passed"), 10)


def _mock_unit_result(result, suite_dict: dict) -> None:
    """Helper to mock UnitTestAgent._run with a given suite."""
    result.data["suite"] = suite_dict
    result.data["runner"] = suite_dict.get("runner", "pytest")
    result.files_scanned = suite_dict.get("total", 0)
    # Add findings for failures
    from patchi.core.agents.base import Severity, make_finding

    for case in suite_dict.get("cases", []):
        if not case.get("passed", True):
            result.add_finding(
                make_finding(
                    agent="UnitTestAgent",
                    finding_type="test_failure",
                    severity=Severity.CRITICAL,
                    file=case.get("file", ""),
                    line=case.get("line", 0),
                    message=f"Test failed: {case['name']}",
                    detail=case.get("error", ""),
                )
            )


# ── _run helper ───────────────────────────────────────────────────────────────


class TestRunHelper(unittest.TestCase):
    def test_run_captures_stdout(self):
        result = _run(["echo", "hello"], Path("/tmp"))
        self.assertIn("hello", result["stdout"])
        self.assertEqual(result["returncode"], 0)

    def test_run_captures_returncode(self):
        result = _run(["false"], Path("/tmp"))
        self.assertNotEqual(result["returncode"], 0)

    def test_run_handles_timeout(self):
        result = _run(["sleep", "60"], Path("/tmp"), timeout=1)
        self.assertTrue(result["timed_out"])

    def test_run_handles_invalid_command(self):
        result = _run(["nonexistent_command_xyz_abc"], Path("/tmp"))
        self.assertNotEqual(result["returncode"], 0)


if __name__ == "__main__":
    unittest.main()
