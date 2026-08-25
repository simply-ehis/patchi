"""Tests for patchi.core.agents.governor.GovernorEngine (incident state machine)."""

import tempfile
import time
import unittest
from pathlib import Path

from patchi.core.agents.governor import (
    Condition,
    GovernorEngine,
    Incident,
    IncidentState,
)


class _EngTestCase(unittest.TestCase):
    """Base class with cleanup for GovernorEngine tests."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name) / "testproj"
        self.root.mkdir()
        self.engine = GovernorEngine(self.root)

    def tearDown(self):
        self.engine.governor.close()
        self.engine = None
        _cleanup_tmpdir(self.tmpdir)

def _cleanup_tmpdir(tmpdir: tempfile.TemporaryDirectory) -> None:
    import gc
    import os
    import time
    p = Path(tmpdir.name)
    # Remove stale SQLite WAL/SHM files that Windows still holds
    for f in p.rglob("*.db-wal"):
        try: os.remove(f)
        except OSError: pass
    for f in p.rglob("*.db-shm"):
        try: os.remove(f)
        except OSError: pass
    gc.collect()
    time.sleep(0.05)
    for _ in range(5):
        try:
            tmpdir.cleanup()
            return
        except PermissionError:
            time.sleep(0.1)
    tmpdir.cleanup()


class TestIncidentState(unittest.TestCase):
    def test_terminal_states(self):
        self.assertTrue(IncidentState.VERIFIED_RESOLVED.is_terminal)
        self.assertTrue(IncidentState.AWAITING_HUMAN_DECISION.is_terminal)
        self.assertTrue(IncidentState.FLAGGED_OPEN.is_terminal)

    def test_non_terminal_states(self):
        self.assertFalse(IncidentState.DETECTED.is_terminal)
        self.assertFalse(IncidentState.CLASSIFIED.is_terminal)
        self.assertFalse(IncidentState.ESCALATED_TO_HUMAN.is_terminal)

    def test_enum_values(self):
        self.assertEqual(IncidentState.DETECTED.value, "detected")
        self.assertEqual(IncidentState.CLASSIFIED.value, "classified")
        self.assertEqual(IncidentState.ESCALATED_TO_HUMAN.value, "escalated_to_human")


class TestCreateIncident(_EngTestCase):
    def test_create_minimal_incident(self):
        inc = self.engine.create_incident(control_id="C-001", confidence=0.8)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.control_id, "C-001")
        self.assertEqual(inc.state, IncidentState.DETECTED)
        self.assertEqual(inc.confidence, 0.8)
        self.assertEqual(len(inc.audit_trail), 1)

    def test_create_from_finding_dict(self):
        finding = {
            "control_id": "C-002",
            "technique_id": "T-101",
            "confidence": 0.95,
            "affected_node": {"symbol": "auth.login", "criticality": "auth"},
        }
        inc = self.engine.create_incident(finding_dict=finding)
        self.assertEqual(inc.control_id, "C-002")
        self.assertEqual(inc.technique_id, "T-101")
        self.assertEqual(inc.confidence, 0.95)
        self.assertEqual(inc.symbol_id, "auth.login")
        self.assertEqual(inc.criticality, "auth")

    def test_create_from_finding_dict_no_affected_node(self):
        finding = {"control_id": "C-003", "confidence": 0.7}
        inc = self.engine.create_incident(finding_dict=finding)
        self.assertEqual(inc.control_id, "C-003")
        self.assertEqual(inc.symbol_id, None)

    def test_incident_id_format(self):
        inc = self.engine.create_incident(control_id="C-004")
        self.assertTrue(inc.id.startswith("INC-"))

    def test_create_increments_count(self):
        self.engine.create_incident(control_id="C-005")
        self.assertEqual(len(self.engine._incidents), 1)
        self.engine.create_incident(control_id="C-006")
        self.assertEqual(len(self.engine._incidents), 2)

    def test_create_with_all_fields(self):
        inc = self.engine.create_incident(
            control_id="C-007",
            symbol_id="user.login",
            technique_id="T-202",
            confidence=0.99,
            criticality="secrets",
            check_method="static-analysis",
            bug_class="semantic-mismatch",
            domain_activation_state="active",
        )
        self.assertEqual(inc.symbol_id, "user.login")
        self.assertEqual(inc.technique_id, "T-202")
        self.assertEqual(inc.criticality, "secrets")
        self.assertEqual(inc.check_method, "static-analysis")
        self.assertEqual(inc.bug_class, "semantic-mismatch")
        self.assertEqual(inc.domain_activation_state, "active")


class TestTransitionIncident(_EngTestCase):
    def test_transition_to_new_state(self):
        inc = self.engine.create_incident(control_id="C-010")
        self.engine.transition_incident(inc.id, IncidentState.CLASSIFIED, rule_id="manual")
        updated = self.engine.get_incident(inc.id)
        self.assertEqual(updated.state, IncidentState.CLASSIFIED)
        self.assertEqual(len(updated.audit_trail), 2)

    def test_transition_unknown_incident_returns_none(self):
        result = self.engine.transition_incident("NONEXISTENT", IncidentState.CLASSIFIED)
        self.assertIsNone(result)

    def test_transition_appends_audit_entry(self):
        inc = self.engine.create_incident(control_id="C-011")
        self.engine.transition_incident(inc.id, IncidentState.CLASSIFIED, rule_id="r1", metadata={"source": "test"})
        self.engine.transition_incident(inc.id, IncidentState.TEST_SCOPED, rule_id="r2")
        self.assertEqual(len(inc.audit_trail), 3)

    def test_persist_after_transition(self):
        inc = self.engine.create_incident(control_id="C-012")
        self.engine.transition_incident(inc.id, IncidentState.VERIFIED_RESOLVED, rule_id="resolve")
        with self.engine.governor._get_conn() as conn:
            row = conn.execute("SELECT state FROM incidents WHERE id = ?", (inc.id,)).fetchone()
        self.assertEqual(row[0], "verified_resolved")


class TestGetIncidents(_EngTestCase):
    def test_get_all_incidents(self):
        self.engine.create_incident(control_id="C-020")
        self.engine.create_incident(control_id="C-021")
        all_inc = self.engine.get_incidents()
        self.assertEqual(len(all_inc), 2)

    def test_get_incidents_by_state(self):
        i1 = self.engine.create_incident(control_id="C-022")
        self.engine.create_incident(control_id="C-023")
        self.engine.transition_incident(i1.id, IncidentState.CLASSIFIED, rule_id="r")
        classified = self.engine.get_incidents(IncidentState.CLASSIFIED)
        self.assertEqual(len(classified), 1)
        self.assertEqual(classified[0].id, i1.id)


class TestDispatchRules(_EngTestCase):
    def test_load_rules_no_dir(self):
        engine = GovernorEngine(self.root / "empty")
        self.assertEqual(len(engine._rules), 0)

    def test_load_rules_from_yaml(self):
        rules_dir = self.root / ".patchi" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / "test_rule.yaml").write_text("""rule_id: test-001
applies_at_state: DETECTED
priority: 10
conditions:
  - field: finding.confidence
    operator: ">="
    value: 0.8
action:
  type: transition
  next_state: CLASSIFIED
  reason: high-confidence-auto-classify
""")
        engine = GovernorEngine(self.root)
        self.assertEqual(len(engine._rules), 1)
        rule = engine._rules[0]
        self.assertEqual(rule.rule_id, "test-001")
        self.assertEqual(rule.applies_at_state, "DETECTED")
        self.assertEqual(len(rule.conditions), 1)
        self.assertEqual(rule.action.next_state, "CLASSIFIED")

    def test_evaluate_conditions_confidence_ge(self):
        cond = Condition(field="finding.confidence", operator=">=", value=0.8)
        inc = Incident(
            id="INC-1", state=IncidentState.DETECTED,
            control_id="C-1", symbol_id=None, technique_id=None, confidence=0.9,
        )
        result = self.engine
        self.assertTrue(result._evaluate_conditions(inc, [cond]))

    def test_evaluate_conditions_confidence_below(self):
        cond = Condition(field="finding.confidence", operator=">=", value=0.8)
        inc = Incident(
            id="INC-1", state=IncidentState.DETECTED,
            control_id="C-1", symbol_id=None, technique_id=None, confidence=0.5,
        )
        self.assertFalse(self.engine._evaluate_conditions(inc, [cond]))

    def test_unknown_operator_returns_false(self):
        cond = Condition(field="finding.confidence", operator="??", value=0.8)
        inc = Incident(
            id="INC-1", state=IncidentState.DETECTED,
            control_id="C-1", symbol_id=None, technique_id=None, confidence=0.9,
        )
        self.assertFalse(self.engine._evaluate_conditions(inc, [cond]))

    def test_evaluate_dispatch_rules_first_match(self):
        rules_dir = self.root / ".patchi" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / "high.yaml").write_text("""rule_id: high-conf
applies_at_state: detected
priority: 10
conditions:
  - field: finding.confidence
    operator: ">="
    value: 0.8
action:
  type: transition
  next_state: CLASSIFIED
""")
        (rules_dir / "low.yaml").write_text("""rule_id: low-conf
applies_at_state: detected
priority: 20
conditions:
  - field: finding.confidence
    operator: ">="
    value: 0.0
action:
  type: transition
  next_state: CLASSIFIED
""")
        engine = GovernorEngine(self.root)
        inc = engine.create_incident(control_id="C-MATCH", confidence=0.9)
        rule = engine.evaluate_dispatch_rules(inc)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.rule_id, "high-conf")

    def test_no_match_returns_none(self):
        rules_dir = self.root / ".patchi" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        (rules_dir / "high.yaml").write_text("""rule_id: high-conf
applies_at_state: DETECTED
priority: 10
conditions:
  - field: finding.confidence
    operator: ">="
    value: 0.8
action:
  type: transition
  next_state: CLASSIFIED
""")
        engine = GovernorEngine(self.root)
        inc = engine.create_incident(control_id="C-NOMATCH", confidence=0.3)
        rule = engine.evaluate_dispatch_rules(inc)
        self.assertIsNone(rule)

    def test_resolve_field_dotted(self):
        inc = Incident(
            id="INC-F", state=IncidentState.DETECTED,
            control_id="C-F", symbol_id=None, technique_id="T-F", confidence=0.7,
            bug_class="logic",
        )
        val = self.engine._resolve_field(inc, "finding.technique_id")
        self.assertEqual(val, "T-F")
        val = self.engine._resolve_field(inc, "finding.bug_class")
        self.assertEqual(val, "logic")
        val = self.engine._resolve_field(inc, "id")
        self.assertEqual(val, "INC-F")


class TestEscalationRules(_EngTestCase):
    def test_hard_trigger_criticality_auth(self):
        inc = self.engine.create_incident(
            control_id="C-HARD", criticality="auth", confidence=0.9,
        )
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_SCORING, rule_id="phase")
        reason = self.engine.check_hard_escalation_triggers(inc)
        self.assertEqual(reason, "hard-trigger-criticality")

    def test_hard_trigger_manual_review(self):
        inc = self.engine.create_incident(
            control_id="C-MANUAL", check_method="manual-review", confidence=0.9,
        )
        self.engine.transition_incident(inc.id, IncidentState.CLASSIFIED, rule_id="phase")
        reason = self.engine.check_hard_escalation_triggers(inc)
        self.assertEqual(reason, "hard-trigger-manual-review")

    def test_hard_trigger_semantic_mismatch(self):
        inc = self.engine.create_incident(
            control_id="C-SEM", bug_class="semantic-mismatch", confidence=0.9,
        )
        self.engine.transition_incident(inc.id, IncidentState.TEST_COMPLETE, rule_id="phase")
        reason = self.engine.check_hard_escalation_triggers(inc)
        self.assertEqual(reason, "hard-trigger-semantic-mismatch")

    def test_hard_trigger_unclear_domain(self):
        inc = self.engine.create_incident(
            control_id="C-DOM", domain_activation_state="unclear", confidence=0.9,
        )
        self.engine.transition_incident(inc.id, IncidentState.CLASSIFIED, rule_id="phase")
        reason = self.engine.check_hard_escalation_triggers(inc)
        self.assertEqual(reason, "hard-trigger-unclear-domain")

    def test_no_hard_trigger_when_wrong_state(self):
        inc = self.engine.create_incident(
            control_id="C-HARD", criticality="auth", confidence=0.9,
        )
        reason = self.engine.check_hard_escalation_triggers(inc)
        self.assertIsNone(reason)

    def test_score_escalation_below_threshold(self):
        inc = self.engine.create_incident(control_id="C-SCORE", confidence=0.9)
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_SCORING, rule_id="phase")
        reason = self.engine.check_score_escalation(inc, best_score=0.5)
        self.assertIsNotNone(reason)
        self.assertIn("score-below-threshold", reason)

    def test_score_escalation_above_threshold(self):
        inc = self.engine.create_incident(control_id="C-SCORE2", confidence=0.9)
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_SCORING, rule_id="phase")
        reason = self.engine.check_score_escalation(inc, best_score=0.9)
        self.assertIsNone(reason)

    def test_score_escalation_wrong_state(self):
        inc = self.engine.create_incident(control_id="C-SCORE3", confidence=0.9)
        reason = self.engine.check_score_escalation(inc, best_score=0.3)
        self.assertIsNone(reason)

    def test_rate_limiting_max_retries(self):
        self.engine._max_fix_retries = 2
        inc = self.engine.create_incident(control_id="C-RATE", confidence=0.9)
        inc.fix_retries = 3
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_GENERATION, rule_id="phase")
        reason = self.engine.check_rate_limiting(inc)
        self.assertEqual(reason, "max-fix-retries-exceeded")

    def test_rate_limiting_dispatch_window(self):
        now = time.time()
        self.engine._max_dispatches_per_window = 3
        self.engine._dispatch_timestamps.extend([now - 1, now - 2, now - 3])
        self.engine._dispatch_window_seconds = 10
        inc = self.engine.create_incident(control_id="C-RATE2", confidence=0.9)
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_GENERATION, rule_id="phase")
        reason = self.engine.check_rate_limiting(inc)
        self.assertEqual(reason, "dispatch-rate-exceeded")

    def test_rate_limiting_under_limit(self):
        self.engine._max_dispatches_per_window = 10
        inc = self.engine.create_incident(control_id="C-RATE3", confidence=0.9)
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_GENERATION, rule_id="phase")
        reason = self.engine.check_rate_limiting(inc)
        self.assertIsNone(reason)

    def test_combined_escalation_hard_takes_precedence(self):
        inc = self.engine.create_incident(
            control_id="C-COMBO", criticality="secrets", confidence=0.9,
        )
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_SCORING, rule_id="phase")
        reason = self.engine.check_escalation(inc, best_score=0.3)
        self.assertEqual(reason, "hard-trigger-criticality")

    def test_combined_escalation_score_fallback(self):
        inc = self.engine.create_incident(control_id="C-COMBO2", confidence=0.9)
        self.engine.transition_incident(inc.id, IncidentState.FIX_CANDIDATE_SCORING, rule_id="phase")
        reason = self.engine.check_escalation(inc, best_score=0.3)
        self.assertIn("score-below-threshold", reason)


class TestDispatchTracking(_EngTestCase):
    def test_can_dispatch_under_limit(self):
        self.assertTrue(self.engine.can_dispatch())

    def test_cannot_dispatch_over_limit(self):
        import time
        now = time.time()
        self.engine._max_dispatches_per_window = 2
        self.engine._dispatch_timestamps.extend([now - 1, now - 2])
        self.engine._dispatch_window_seconds = 10
        self.assertFalse(self.engine.can_dispatch())

    def test_record_dispatch_adds_timestamp(self):
        before = len(self.engine._dispatch_timestamps)
        self.engine.record_dispatch(incident_id="INC-TEST")
        self.assertEqual(len(self.engine._dispatch_timestamps), before + 1)


class TestPhaseMapping(_EngTestCase):
    def test_map_scan_to_classified(self):
        from patchi.core.agents.governor import PipelinePhase
        state = self.engine._map_phase_to_incident_state(PipelinePhase.SCAN)
        self.assertEqual(state, IncidentState.CLASSIFIED)

    def test_map_test_generation_to_test_scoped(self):
        from patchi.core.agents.governor import PipelinePhase
        state = self.engine._map_phase_to_incident_state(PipelinePhase.TEST_GENERATION)
        self.assertEqual(state, IncidentState.TEST_SCOPED)

    def test_map_test_execution_to_test_complete(self):
        from patchi.core.agents.governor import PipelinePhase
        state = self.engine._map_phase_to_incident_state(PipelinePhase.TEST_EXECUTION)
        self.assertEqual(state, IncidentState.TEST_COMPLETE)

    def test_map_fix_generation_to_fix_candidate(self):
        from patchi.core.agents.governor import PipelinePhase
        state = self.engine._map_phase_to_incident_state(PipelinePhase.FIX_GENERATION)
        self.assertEqual(state, IncidentState.FIX_CANDIDATE_GENERATION)

    def test_map_complete_and_failed_to_none(self):
        from patchi.core.agents.governor import PipelinePhase
        self.assertIsNone(self.engine._map_phase_to_incident_state(PipelinePhase.COMPLETE))
        self.assertIsNone(self.engine._map_phase_to_incident_state(PipelinePhase.FAILED))


class TestEngineStatus(_EngTestCase):
    def test_status_includes_incident_count(self):
        self.engine.create_incident(control_id="C-100")
        s = self.engine.status()
        self.assertIn("incident_count", s)
        self.assertEqual(s["incident_count"], 1)

    def test_status_includes_incidents_by_state(self):
        s = self.engine.status()
        self.assertIn("incidents_by_state", s)

    def test_status_includes_rules_loaded(self):
        s = self.engine.status()
        self.assertIn("rules_loaded", s)

    def test_reset_clears_incidents(self):
        self.engine.create_incident(control_id="C-101")
        self.engine.reset()
        self.assertEqual(len(self.engine._incidents), 0)
        self.assertEqual(self.engine.governor.current_phase.value, "idle")


if __name__ == "__main__":
    unittest.main()
