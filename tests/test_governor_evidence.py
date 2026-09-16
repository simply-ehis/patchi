"""Governor evidence machinery (spec §2): verdicts carry proof, gates bite."""

import tempfile
from pathlib import Path

from patchi.core.agents.base import AgentResult, AgentStatus
from patchi.core.agents.governor import Governor, PipelinePhase


def _gov():
    t = Path(tempfile.mkdtemp())
    (t / ".patchi").mkdir(exist_ok=True)
    g = Governor(t)
    return g, t


def _res(name, status=AgentStatus.DONE, data=None, findings=0):
    r = AgentResult(agent_name=name, status=status)
    r.data.update(data or {})
    return r


def test_scan_carries_eval_evidence():
    g, t = _gov()
    try:
        g.current_phase = PipelinePhase.IDLE
        pr = g._transition_to(PipelinePhase.SCAN, [_res("S")])
        ev = pr.data["evidence"]
        assert ev["eval"]["eval_ok"] is True
        assert ev["eval"]["routing_accuracy"] == 1.0
        assert pr.data["verdict"] in ("done", "partial")
    finally:
        g.close()


def test_failing_tests_hard_block_execution():
    g, t = _gov()
    try:
        g.current_phase = PipelinePhase.TEST_GENERATION
        pr = g._transition_to(
            PipelinePhase.TEST_EXECUTION,
            [_res("UT", data={"suite": {"passed": 5, "failed": 2, "skipped": 0, "errors": 0}})],
        )
        assert pr.status == AgentStatus.FAILED
        assert any("block progression" in e for e in pr.errors)
        assert pr.data["verdict"] == "failed"
    finally:
        g.close()


def test_flaky_suite_fails_execution():
    g, t = _gov()
    try:
        g.current_phase = PipelinePhase.TEST_GENERATION
        pr = g._transition_to(
            PipelinePhase.TEST_EXECUTION,
            [
                _res("UT", data={"suite": {"passed": 5, "failed": 0, "skipped": 0, "errors": 0}}),
                _res("Flake", data={"flaky_tests": 3}),
            ],
        )
        assert pr.status == AgentStatus.FAILED
        assert any("Flaky" in e for e in pr.errors)
    finally:
        g.close()


def test_fix_candidate_composite_logged():
    g, t = _gov()
    try:
        verify = {"verified": ["p1"], "applied_unverified": [], "review_required": [], "rolled_back": []}
        r = _res(
            "Fixer",
            data={
                "patches": [
                    {"id": "p1", "blast_radius": 2},
                    {"id": "p2", "blast_radius": 12},
                ]
            },
        )
        scored = g._score_fix_candidate(r, verify)
        assert scored["breakdown"]["verified"] == 1
        assert scored["breakdown"]["patches"] == 2
        assert scored["breakdown"]["tests_pass"] == 0.5
        assert scored["breakdown"]["max_blast_radius"] == 12
        assert scored["breakdown"]["mutation"] == "unmeasured"
        assert 0.0 <= scored["score"] <= 1.0
    finally:
        g.close()


def test_seeded_high_criticality_escalates():
    """Spec §2 SCORE_SELECT: a restricted-path patch escalates even at 0.95."""
    import json

    g, t = _gov()
    try:
        cfg = {
            "restrictions": [
                {"path": "prod/creds.env", "type": "no_touch", "enabled": True}
            ]
        }
        (t / ".patchi" / "config.json").write_text(json.dumps(cfg), encoding="utf-8")
        r = _res(
            "Fixer",
            data={
                "patches": [
                    {
                        "id": "p9",
                        "patch_type": "bug_fix",
                        "blast_radius": 1,
                        "changes": [
                            {"path": "prod/creds.env", "original": "a", "proposed": "b"}
                        ],
                    }
                ]
            },
        )
        candidate = {"agent_name": "Fixer", "score": 0.95, "findings": 0}
        decision = g._select_candidate(candidate, r)
        assert decision["action"] == "escalate", decision
        assert "risk_gate" in decision["reason"]
    finally:
        g.close()


def test_empty_execution_is_partial_not_done():
    # A clean run with no test outcomes reported is "partial", never "done".
    g, t = _gov()
    try:
        g.current_phase = PipelinePhase.TEST_GENERATION
        pr = g._transition_to(PipelinePhase.TEST_EXECUTION, [])
        assert pr.data["verdict"] == "partial"
        assert any("no agent reported" in r for r in pr.data["evidence"]["partial_reasons"])
    finally:
        g.close()


def test_close_commit_failure_returns_false():
    """Part 8 §4: Governor.close() must surface commit failures, not swallow them."""
    import sqlite3 as _sqlite3

    g, t = _gov()
    try:
        # sqlite3.Connection is a C type — can't monkey-patch. Instead,
        # replace _conn with a thin wrapper that fails on commit.
        class _FailConn:
            """Wraps a real sqlite3.Connection; commit() always fails."""

            def __init__(self, real: _sqlite3.Connection):
                object.__setattr__(self, "_real", real)

            def commit(self):
                raise _sqlite3.OperationalError("database is locked")

            def __getattr__(self, name):
                return getattr(object.__getattribute__(self, "_real"), name)

        g._conn = _FailConn(g._conn)
        result = g.close()
        assert result is False, "close() should return False when commit fails"
        assert g._conn is None
    finally:
        if g._conn is not None:
            g.close()
