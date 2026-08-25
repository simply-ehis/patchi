"""Tests for patchi.core.agents.governor v2 pipeline."""

import tempfile
import unittest
from pathlib import Path

from patchi.core.agents.base import AgentGroup, AgentStatus
from patchi.core.agents.governor import (
    DEFAULT_CRITERIA,
    Governor,
    PhaseCriteria,
    PipelinePhase,
)


class TestPipelinePhase(unittest.TestCase):
    def test_order_values(self):
        self.assertEqual(PipelinePhase.IDLE.order, 0)
        self.assertEqual(PipelinePhase.SCAN.order, 1)
        self.assertEqual(PipelinePhase.GRAPH_UPDATE.order, 2)
        self.assertEqual(PipelinePhase.TEST_GENERATION.order, 3)
        self.assertEqual(PipelinePhase.TEST_EXECUTION.order, 4)
        self.assertEqual(PipelinePhase.FIX_GENERATION.order, 5)
        self.assertEqual(PipelinePhase.SANDBOX_REVERIFY.order, 6)
        self.assertEqual(PipelinePhase.SCORE_SELECT.order, 7)
        self.assertEqual(PipelinePhase.COMPLETE.order, 8)
        self.assertEqual(PipelinePhase.FAILED.order, -1)

    def test_next_phase_sequential(self):
        self.assertEqual(PipelinePhase.SCAN.next_phase, PipelinePhase.GRAPH_UPDATE)
        self.assertEqual(PipelinePhase.GRAPH_UPDATE.next_phase, PipelinePhase.TEST_GENERATION)
        self.assertEqual(PipelinePhase.TEST_GENERATION.next_phase, PipelinePhase.TEST_EXECUTION)
        self.assertEqual(PipelinePhase.TEST_EXECUTION.next_phase, PipelinePhase.FIX_GENERATION)
        self.assertEqual(PipelinePhase.FIX_GENERATION.next_phase, PipelinePhase.SANDBOX_REVERIFY)
        self.assertEqual(PipelinePhase.SANDBOX_REVERIFY.next_phase, PipelinePhase.SCORE_SELECT)
        self.assertEqual(PipelinePhase.SCORE_SELECT.next_phase, PipelinePhase.COMPLETE)

    def test_failed_terminal(self):
        self.assertIsNone(PipelinePhase.FAILED.next_phase)

    def test_complete_terminal(self):
        self.assertIsNone(PipelinePhase.COMPLETE.next_phase)

    def test_is_valid_transition(self):
        self.assertTrue(PipelinePhase.is_valid_transition(PipelinePhase.IDLE, PipelinePhase.SCAN))
        self.assertTrue(PipelinePhase.is_valid_transition(PipelinePhase.SCAN, PipelinePhase.GRAPH_UPDATE))
        self.assertTrue(PipelinePhase.is_valid_transition(PipelinePhase.GRAPH_UPDATE, PipelinePhase.TEST_GENERATION))
        self.assertTrue(PipelinePhase.is_valid_transition(PipelinePhase.COMPLETE, PipelinePhase.SCAN))

    def test_invalid_transition(self):
        self.assertFalse(PipelinePhase.is_valid_transition(PipelinePhase.IDLE, PipelinePhase.FIX_GENERATION))
        self.assertFalse(PipelinePhase.is_valid_transition(PipelinePhase.SCAN, PipelinePhase.COMPLETE))


class TestPhaseCriteria(unittest.TestCase):
    def test_default_criteria_have_all_phases(self):
        required = [
            PipelinePhase.SCAN,
            PipelinePhase.GRAPH_UPDATE,
            PipelinePhase.TEST_GENERATION,
            PipelinePhase.TEST_EXECUTION,
            PipelinePhase.FIX_GENERATION,
            PipelinePhase.SANDBOX_REVERIFY,
            PipelinePhase.SCORE_SELECT,
        ]
        for phase in required:
            self.assertIn(phase, DEFAULT_CRITERIA)

    def test_passed_default(self):
        result = PhaseCriteria()
        self.assertEqual(result.max_errors, 0)
        self.assertEqual(result.min_agents_run, 1)

    def test_custom_criteria(self):
        c = PhaseCriteria(max_errors=10, max_critical_findings=5, require_zero_errors=False)
        self.assertEqual(c.max_errors, 10)
        self.assertEqual(c.max_critical_findings, 5)
        self.assertFalse(c.require_zero_errors)


class _GovTestCase(unittest.TestCase):
    """Base class with proper cleanup for Governor tests."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name) / "testproj"
        self.root.mkdir()
        self.gov = Governor(self.root)

    def tearDown(self):
        try:
            self.gov.close()
        except Exception:
            pass
        self.gov = None
        import gc
        gc.collect()
        self.tmpdir.cleanup()


class TestGovernorInitialization(_GovTestCase):
    def test_initial_phase_is_idle(self):
        self.assertEqual(self.gov.current_phase, PipelinePhase.IDLE)

    def test_status_dict_has_required_keys(self):
        s = self.gov.status()
        self.assertIn("current_phase", s)
        self.assertIn("phase_order", s)
        self.assertIn("next_phase", s)
        self.assertIn("is_running", s)
        self.assertIn("recent_history", s)


class TestGraphNeighborhood(_GovTestCase):
    def test_empty_symbols_returns_empty(self):
        result = self.gov._build_graph_neighborhood([])
        self.assertEqual(result, [])

    def test_unknown_symbols_skipped_gracefully(self):
        result = self.gov._build_graph_neighborhood(["nobody_exists"])
        self.assertEqual(result, [])


class TestScoreFixCandidate(_GovTestCase):

    def test_done_status_scores_high(self):
        from patchi.core.agents.base import AgentResult, AgentStatus

        r = AgentResult(
            agent_name="TestFixer",
            agent_group="FIX",
            status=AgentStatus.DONE,
        )
        score = self.gov._score_fix_candidate(r)
        self.assertGreater(score, 0.5)

    def test_failed_status_scores_low(self):
        from patchi.core.agents.base import AgentResult, AgentStatus, Finding, Severity

        findings = [Finding(agent="scan", type="bug", severity=Severity.HIGH, file="x.py")]
        r = AgentResult(
            agent_name="TestFixer",
            agent_group="FIX",
            status=AgentStatus.FAILED,
            findings=findings,
        )
        score = self.gov._score_fix_candidate(r)
        self.assertLess(score, 0.5)

    def test_many_findings_reduces_score(self):
        from patchi.core.agents.base import AgentResult, AgentStatus, Finding, Severity

        r1 = AgentResult(agent_name="A", agent_group="FIX", status=AgentStatus.DONE)
        findings = [Finding(agent="scan", type="bug", severity=Severity.HIGH, file=f"x{i}.py") for i in range(25)]
        r2 = AgentResult(agent_name="B", agent_group="FIX", status=AgentStatus.DONE, findings=findings)
        self.assertGreater(
            self.gov._score_fix_candidate(r1),
            self.gov._score_fix_candidate(r2),
        )


class TestSelectCandidate(_GovTestCase):

    def test_high_score_auto_applies(self):
        from patchi.core.agents.base import AgentResult, AgentStatus

        result = AgentResult(
            agent_name="PerfectFixer",
            agent_group="FIX",
            status=AgentStatus.DONE,
        )
        decision = self.gov._select_candidate(
            {"score": 0.95, "findings": 0, "agent_name": "PerfectFixer"}, result
        )
        self.assertEqual(decision["action"], "auto_apply")

    def test_agent_failure_discards(self):
        from patchi.core.agents.base import AgentResult, AgentStatus

        result = AgentResult(
            agent_name="BrokenFixer",
            agent_group="FIX",
            status=AgentStatus.FAILED,
        )
        decision = self.gov._select_candidate(
            {"score": 0.9, "findings": 0, "agent_name": "BrokenFixer"}, result
        )
        self.assertEqual(decision["action"], "discard")

    def test_remaining_findings_escalates(self):
        from patchi.core.agents.base import AgentResult, AgentStatus, Finding, Severity

        findings = [Finding(agent="s", type="t", severity=Severity.HIGH, file="x.py")]
        result = AgentResult(
            agent_name="PartialFixer",
            agent_group="FIX",
            status=AgentStatus.DONE,
            findings=findings,
        )
        decision = self.gov._select_candidate(
            {"score": 0.85, "findings": 1, "agent_name": "PartialFixer"}, result
        )
        self.assertEqual(decision["action"], "escalate")

    def test_moderate_score_escalates(self):
        from patchi.core.agents.base import AgentResult, AgentStatus

        result = AgentResult(
            agent_name="ModerateFixer",
            agent_group="FIX",
            status=AgentStatus.DONE,
        )
        decision = self.gov._select_candidate(
            {"score": 0.6, "findings": 0, "agent_name": "ModerateFixer"}, result
        )
        self.assertEqual(decision["action"], "escalate")

    def test_low_score_discards(self):
        from patchi.core.agents.base import AgentResult, AgentStatus

        result = AgentResult(
            agent_name="WeakFixer",
            agent_group="FIX",
            status=AgentStatus.DONE,
        )
        decision = self.gov._select_candidate(
            {"score": 0.3, "findings": 0, "agent_name": "WeakFixer"}, result
        )
        self.assertEqual(decision["action"], "discard")


class TestGovernorVerifyLoop(_GovTestCase):
    """The Governor's FIX phase must route produced patches through the
    fix→verify→retry loop (verify_loop) exactly like `p fix` does: applier
    injected, test-weakening patches flagged for review (never auto-applied),
    and verified vs applied-but-unverified outcomes reported in the phase
    result; REVERIFY must re-run the SPECIFIC failing tests of applied patches.
    """

    def _fix_result(self, patch_dict: dict):
        from patchi.core.agents.base import AgentResult, AgentStatus

        return AgentResult(
            agent_name="CodeFixer",
            agent_group=AgentGroup.FIX,
            status=AgentStatus.DONE,
            data={"patches": [patch_dict]},
        )

    def _patch_dict(self, path="src/math.py", finding_type="test_failure",
                    test_file="tests/test_math.py", only_tests=False):
        from patchi.core.fix.patch import FileChange, Patch, PatchType

        change_path = test_file if only_tests else path
        patch = Patch(
            agent="CodeFixer",
            patch_type=PatchType.BUG_FIX,
            changes=[
                FileChange(
                    path=change_path,
                    original="x\n",
                    proposed="y\n",
                )
            ],
            description="Fix failing test",
            risk_score=10,
            source_finding={
                "type": finding_type,
                "fix_agent": "CodeFixer",
                "file": test_file,
                "message": "Test failed",
            },
        )
        return patch.to_dict()

    def test_run_fix_routes_patch_through_verify_loop(self):
        """A test_failure patch is applied via run_verify_loop (applier injected)
        and its verified outcome is reported in result.data["verify"]."""
        from unittest.mock import patch as mock_patch

        from patchi.core.fix.verify_loop import VerifyOutcome

        pd = self._patch_dict()
        from patchi.core.fix.patch import Patch

        patch = Patch.from_dict(pd)
        verified_outcome = VerifyOutcome(patch=patch, applied=True, verified=True)

        captured = {}

        def fake_verify_loop(patch, **kwargs):
            captured["applier_injected"] = kwargs.get("applier") is not None
            captured["patch"] = patch
            return verified_outcome

        with mock_patch(
            "patchi.core.fix.verify_loop.run_verify_loop", side_effect=fake_verify_loop
        ), mock_patch.object(
            self.gov.coordinator, "run_group", return_value=[self._fix_result(pd)]
        ):
            result = self.gov.run_fix()

        self.assertEqual(result.phase, PipelinePhase.FIX_GENERATION)
        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertIn("verify", result.data)
        self.assertEqual(result.data["verify"]["verified"], [patch.id])
        self.assertTrue(captured["applier_injected"], "verify loop must receive the applier")
        # Applied patches are remembered for REVERIFY's specific-test recheck.
        self.assertEqual(len(self.gov._last_applied_patches), 1)
        self.assertEqual(self.gov._last_applied_patches[0][1], "tests/test_math.py")

    def test_run_fix_flags_test_only_patch_for_review(self):
        """A patch whose ONLY change is a test file is flagged requires_review
        and is never sent through the verify loop (test-weakening guard)."""
        from unittest.mock import patch as mock_patch

        pd = self._patch_dict(only_tests=True)

        with mock_patch(
            "patchi.core.fix.verify_loop.run_verify_loop",
            side_effect=AssertionError("test-only patch must not be applied"),
        ), mock_patch.object(
            self.gov.coordinator, "run_group", return_value=[self._fix_result(pd)]
        ):
            result = self.gov.run_fix()

        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertEqual(len(result.data["verify"]["review_required"]), 1)
        self.assertEqual(len(result.data["verify"]["verified"]), 0)

    def test_run_fix_dry_run_skips_apply(self):
        """dry_run must not apply anything — verify summary stays empty."""
        from unittest.mock import patch as mock_patch

        pd = self._patch_dict()
        with mock_patch(
            "patchi.core.fix.verify_loop.run_verify_loop",
            side_effect=AssertionError("dry-run must not apply"),
        ), mock_patch.object(
            self.gov.coordinator, "run_group", return_value=[self._fix_result(pd)]
        ):
            result = self.gov.run_fix(dry_run=True)

        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertEqual(result.data["verify"]["verified"], [])
        self.assertEqual(result.data["verify"]["applied_unverified"], [])

    def test_run_fix_reports_applied_but_unverified(self):
        """Applied-but-not-re-verified outcomes are reported separately."""
        from unittest.mock import patch as mock_patch

        from patchi.core.fix.verify_loop import VerifyOutcome

        from patchi.core.fix.patch import Patch

        pd = self._patch_dict()
        patch = Patch.from_dict(pd)
        outcome = VerifyOutcome(
            patch=patch, applied=True, verified=False,
            reason="pytest not installed",
        )
        with mock_patch(
            "patchi.core.fix.verify_loop.run_verify_loop", return_value=outcome
        ), mock_patch.object(
            self.gov.coordinator, "run_group", return_value=[self._fix_result(pd)]
        ):
            result = self.gov.run_fix()

        self.assertEqual(result.data["verify"]["applied_unverified"], [patch.id])
        self.assertEqual(result.data["verify"]["verified"], [])

    def test_run_fix_rolled_back_outcome(self):
        """A patch that exhausts retries is reported as rolled_back."""
        from unittest.mock import patch as mock_patch

        from patchi.core.fix.verify_loop import VerifyOutcome

        from patchi.core.fix.patch import Patch

        pd = self._patch_dict()
        patch = Patch.from_dict(pd)
        outcome = VerifyOutcome(
            patch=patch, applied=False, verified=False,
            retries_used=2, reason="test still failing after max retries",
        )
        with mock_patch(
            "patchi.core.fix.verify_loop.run_verify_loop", return_value=outcome
        ), mock_patch.object(
            self.gov.coordinator, "run_group", return_value=[self._fix_result(pd)]
        ):
            result = self.gov.run_fix()

        self.assertEqual(result.data["verify"]["rolled_back"], [patch.id])

    def test_reverify_rechecks_specific_failing_tests(self):
        """REVERIFY re-runs the SPECIFIC failing test of each applied patch and
        fails the phase when a previously-verified test regresses."""
        from unittest.mock import patch as mock_patch

        from patchi.core.fix.patch import FileChange, Patch, PatchType

        patch = Patch(
            agent="CodeFixer",
            patch_type=PatchType.BUG_FIX,
            changes=[FileChange(path="src/math.py", original="x\n", proposed="y\n")],
            source_finding={"type": "test_failure", "file": "tests/test_math.py"},
        )
        self.gov._last_applied_patches = [(patch, "tests/test_math.py")]

        with mock_patch(
            "patchi.core.fix.verify_loop.recheck_test_file",
            return_value={"passed": True, "output": "ok", "error": ""},
        ), mock_patch.object(self.gov.coordinator, "run_all_scanners", return_value=[]), \
             mock_patch.object(self.gov.coordinator, "run_group", return_value=[]):
            result = self.gov.run_reverify()

        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertIn("reverify", result.data)
        self.assertEqual(result.data["reverify"]["passed"], [patch.id])
        self.assertEqual(result.data["reverify"]["regressed"], [])

    def test_reverify_fails_on_regression(self):
        """A previously-verified test that now fails fails the REVERIFY phase."""
        from unittest.mock import patch as mock_patch

        from patchi.core.fix.patch import FileChange, Patch, PatchType

        patch = Patch(
            agent="CodeFixer",
            patch_type=PatchType.BUG_FIX,
            changes=[FileChange(path="src/math.py", original="x\n", proposed="y\n")],
            source_finding={"type": "test_failure", "file": "tests/test_math.py"},
        )
        self.gov._last_applied_patches = [(patch, "tests/test_math.py")]

        with mock_patch(
            "patchi.core.fix.verify_loop.recheck_test_file",
            return_value={"passed": False, "output": "boom", "error": ""},
        ), mock_patch.object(self.gov.coordinator, "run_all_scanners", return_value=[]), \
             mock_patch.object(self.gov.coordinator, "run_group", return_value=[]):
            result = self.gov.run_reverify()

        self.assertEqual(result.status, AgentStatus.FAILED)
        self.assertEqual(result.data["reverify"]["regressed"], [patch.id])
        self.assertTrue(any("regressed" in e for e in result.errors))

    def test_reverify_skips_patches_without_test_file(self):
        """Patches with no failing test file are simply not rechecked."""
        from unittest.mock import patch as mock_patch

        from patchi.core.fix.patch import FileChange, Patch, PatchType

        patch = Patch(
            agent="CodeFixer",
            patch_type=PatchType.BUG_FIX,
            changes=[FileChange(path="src/math.py", original="x\n", proposed="y\n")],
            source_finding={"type": "parse_error", "file": ""},
        )
        self.gov._last_applied_patches = [(patch, "")]

        with mock_patch.object(self.gov.coordinator, "run_all_scanners", return_value=[]), \
             mock_patch.object(self.gov.coordinator, "run_group", return_value=[]):
            result = self.gov.run_reverify()

        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertEqual(result.data["reverify"]["rechecked"], 0)

    def test_reverify_without_prior_fix_phase_is_safe(self):
        """run_reverify on a governor that never ran a FIX phase must not
        crash — _recheck_applied_patches defaults to no applied patches."""
        from unittest.mock import patch as mock_patch

        with mock_patch.object(self.gov.coordinator, "run_all_scanners", return_value=[]), \
             mock_patch.object(self.gov.coordinator, "run_group", return_value=[]):
            result = self.gov.run_reverify()

        self.assertEqual(result.status, AgentStatus.DONE)
        self.assertEqual(result.data["reverify"]["rechecked"], 0)
        self.assertEqual(result.data["reverify"]["regressed"], [])


class TestScoreSelect(_GovTestCase):

    def test_no_candidates_returns_failed(self):
        result = self.gov.run_score_select()
        self.assertEqual(result.phase, PipelinePhase.SCORE_SELECT)
        self.assertEqual(result.status, "failed")

    def test_single_good_candidate_succeeds(self):
        from patchi.core.agents.base import AgentResult, AgentStatus

        r = AgentResult(
            agent_name="TestFixer",
            agent_group="FIX",
            status=AgentStatus.DONE,
            data={"fix": "ok"},
        )
        self.gov._last_candidates = [{"score": 0.95, "findings": 0, "agent_name": "TestFixer"}]
        self.gov._last_fix_results = [r]
        result = self.gov.run_score_select()
        self.assertEqual(result.status, "done")


if __name__ == "__main__":
    unittest.main()
