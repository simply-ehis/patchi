"""Unit tests for patchi.core.agents.coordinator"""

import tempfile
import unittest
from pathlib import Path

import patchi.core.agents.scanners  # noqa: F401 — trigger registration
from patchi.core import config as cfg
from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
)
from patchi.core.agents.coordinator import (
    Coordinator,
    CoordinatorProgress,
    RunMode,
    _run_agent_safe,
    merge_results,
)


def _setup(tmp: Path) -> Path:
    cfg.init_project(tmp)
    return tmp


# ── Test agents ────────────────────────────────────────────────────────────────


class FastOkAgent(BaseAgent):
    name = "FastOkAgent"
    group = AgentGroup.SCANNER
    timeout = 5

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        result.files_scanned = 1
        result.add_finding(make_finding("FastOkAgent", "test", Severity.LOW, "a.py", "ok"))


class FastFailAgent(BaseAgent):
    name = "FastFailAgent"
    group = AgentGroup.SCANNER
    timeout = 5

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        raise RuntimeError("intentional failure")


class NoFindingsAgent(BaseAgent):
    name = "NoFindingsAgent"
    group = AgentGroup.SCANNER
    timeout = 5

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        result.files_scanned = 5


# Registered in setUp to avoid polluting the global registry


class TestRunAgentSafe(unittest.TestCase):
    def _inp(self) -> AgentInput:
        return AgentInput(root=Path("/tmp"), scope=[], brain={}, config={})

    def test_returns_result_on_success(self):
        result = _run_agent_safe(FastOkAgent(), self._inp())
        self.assertIsInstance(result, AgentResult)
        self.assertEqual(result.status, AgentStatus.DONE)

    def test_returns_failed_result_on_exception(self):
        result = _run_agent_safe(FastFailAgent(), self._inp())
        self.assertEqual(result.status, AgentStatus.FAILED)
        self.assertTrue(len(result.errors) > 0)

    def test_never_raises(self):
        # Should not raise even with a crashing agent
        try:
            _run_agent_safe(FastFailAgent(), self._inp())
        except Exception as e:
            self.fail(f"_run_agent_safe raised unexpectedly: {e}")


class TestCoordinator(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = _setup(Path(self.tmpdir.name))
        from patchi.core.agents.base import deregister
        register(FastOkAgent)
        register(FastFailAgent)
        register(NoFindingsAgent)
        self._deregister = deregister

    def tearDown(self):
        self._deregister(FastOkAgent)
        self._deregister(FastFailAgent)
        self._deregister(NoFindingsAgent)
        self.tmpdir.cleanup()

    def test_run_agents_by_name(self):
        coord = Coordinator(self.root)
        results = coord.run_agents(["FastOkAgent", "NoFindingsAgent"])
        self.assertEqual(len(results), 2)

    def test_run_agents_returns_correct_names(self):
        coord = Coordinator(self.root)
        results = coord.run_agents(["FastOkAgent"])
        self.assertEqual(results[0].agent_name, "FastOkAgent")

    def test_unknown_agent_name_skipped(self):
        coord = Coordinator(self.root)
        results = coord.run_agents(["FastOkAgent", "GhostAgent_XYZ"])
        self.assertEqual(len(results), 1)

    def test_failed_agent_captured_not_raised(self):
        coord = Coordinator(self.root)
        results = coord.run_agents(["FastFailAgent"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, AgentStatus.FAILED)

    def test_progress_callback_called(self):
        events: list[CoordinatorProgress] = []
        coord = Coordinator(self.root, on_progress=events.append)
        coord.run_agents(["FastOkAgent", "NoFindingsAgent"])
        self.assertGreater(len(events), 0)

    def test_progress_total_matches_agent_count(self):
        events: list[CoordinatorProgress] = []
        coord = Coordinator(self.root, on_progress=events.append)
        coord.run_agents(["FastOkAgent", "NoFindingsAgent"])
        last = events[-1]
        self.assertEqual(last.total, 2)

    def test_sequential_mode_runs_all(self):
        coord = Coordinator(self.root, run_mode=RunMode.SEQUENTIAL)
        results = coord.run_agents(["FastOkAgent", "NoFindingsAgent"])
        self.assertEqual(len(results), 2)

    def test_parallel_mode_runs_all(self):
        coord = Coordinator(self.root, run_mode=RunMode.PARALLEL)
        results = coord.run_agents(["FastOkAgent", "NoFindingsAgent"])
        self.assertEqual(len(results), 2)

    def test_run_group_returns_scanner_agents(self):
        coord = Coordinator(self.root)
        results = coord.run_group(AgentGroup.SCANNER)
        names = {r.agent_name for r in results}
        # Should include our registered test agents and the real scanner agents
        self.assertIn("FastOkAgent", names)

    def test_scope_passed_to_agents(self):
        """Agents receive the scope list correctly."""
        received_scopes: list[list[str]] = []

        class ScopeCapture(BaseAgent):
            name = "ScopeCapture"
            group = AgentGroup.SCANNER

            def _run(self, inp: AgentInput, result: AgentResult) -> None:
                received_scopes.append(inp.scope)

        register(ScopeCapture)
        coord = Coordinator(self.root)
        coord.run_agents(["ScopeCapture"], scope=["src/app.py", "src/utils.py"])
        self.assertEqual(received_scopes[-1], ["src/app.py", "src/utils.py"])
        self._deregister(ScopeCapture)

    def test_empty_agent_list(self):
        coord = Coordinator(self.root)
        results = coord.run_agents([])
        self.assertEqual(results, [])


class TestMergeResults(unittest.TestCase):
    def _result(self, name: str, findings: list, failed: bool = False) -> AgentResult:
        r = AgentResult(
            agent_name=name,
            agent_group=AgentGroup.SCANNER,
            status=AgentStatus.FAILED if failed else AgentStatus.DONE,
            duration_ms=42,
            files_scanned=3,
        )
        for f in findings:
            r.findings.append(f)
        return r

    def test_merge_combines_findings(self):
        r1 = self._result("A", [make_finding("A", "t", Severity.HIGH, "a.py", "m")])
        r2 = self._result("B", [make_finding("B", "t", Severity.MEDIUM, "b.py", "m")])
        merged = merge_results([r1, r2])
        self.assertEqual(merged["total_findings"], 2)

    def test_merge_sorts_by_severity(self):
        r1 = self._result("A", [make_finding("A", "t", Severity.LOW, "a.py", "m")])
        r2 = self._result("B", [make_finding("B", "t", Severity.HIGH, "b.py", "m")])
        merged = merge_results([r1, r2])
        findings = merged["findings"]
        self.assertEqual(findings[0]["severity"], "high")

    def test_merge_totals_duration(self):
        r1 = self._result("A", [])
        r2 = self._result("B", [])
        r1.duration_ms = 100
        r2.duration_ms = 200
        merged = merge_results([r1, r2])
        self.assertEqual(merged["total_ms"], 300)

    def test_merge_totals_files(self):
        r1 = self._result("A", [])
        r2 = self._result("B", [])
        r1.files_scanned = 5
        r2.files_scanned = 7
        merged = merge_results([r1, r2])
        self.assertEqual(merged["total_files"], 12)

    def test_merge_empty_list(self):
        merged = merge_results([])
        self.assertEqual(merged["total_findings"], 0)
        self.assertEqual(merged["agent_count"], 0)

    def test_merge_includes_agent_data(self):
        r1 = self._result("AgentX", [])
        r1.data["file_count"] = 10
        merged = merge_results([r1])
        self.assertIn("AgentX", merged["by_agent"])
        self.assertEqual(merged["by_agent"]["AgentX"]["file_count"], 10)


if __name__ == "__main__":
    unittest.main()
