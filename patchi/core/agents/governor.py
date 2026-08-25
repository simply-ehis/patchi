"""
Governor — Pipeline state machine wrapping Coordinator.

Phases (v2, per files-5 Testing Strategy §3):
  SCAN           — Structural pass: rules, dangling edges, CVEs, secrets
  GRAPH_UPDATE   — Incremental SymbolGraph patch from scan diff
  TEST_GENERATION — Graph-scoped test generation using neighborhood context
  TEST_EXECUTION  — Run generated tests, results become oracle for fix verify
  FIX_GENERATION  — Multiple candidates with deterministic autofix first, LLM fallback
  SANDBOX_REVERIFY — Re-run scoped tests + loop-back scan on each candidate
  SCORE_SELECT   — Composite scoring → select winner or escalate to human

Design:
  - Additive — wraps Coordinator. Coordinator still works standalone.
  - State is stored in SQLite (.patchi/pipeline_state.db) for crash recovery.
  - Phase transitions gated by acceptance criteria (max errors, findings, etc).
  - Structured finding format enforced across all ants.
  - Ambiguous findings → explicit escalation rule, never model guessing.

Usage:
    gov = Governor(project_root)
    gov.run_full_pipeline_v2()  # Full 7-step pipeline
"""

from __future__ import annotations

import sqlite3
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import yaml
from loguru import logger

import patchi.core.agents.scanners  # noqa: F401 — trigger scanner registration

# Trigger security agent registration. Security agents register lazily inside
# security_agents.py, so the module MUST be imported or Coordinator.
# run_group(AgentGroup.SECURITY) would resolve zero agents.
try:
    import patchi.core.security.security_agents  # noqa: F401
except Exception as e:
    logger.debug(f"security_agents not available: {e}")

# Trigger test agent registration (pulled in via test_agents.py)
try:
    import patchi.core.testing.test_agents  # noqa: F401
except Exception as e:
    logger.debug(f"test_agents not available: {e}")

# Trigger fix agent registration. fix/__init__ imports code_fixer,
# dead_code_remover, and security_fixer; code_fixer imports fix_agents, so all
# 8 FIX agents register. Without this, run_group(AgentGroup.FIX) resolves ZERO
# agents and the pipeline's FIX phase silently runs nothing (caught by the
# smoke-sweep --pipeline orchestration gate).
try:
    import patchi.core.fix  # noqa: F401
except Exception as e:
    logger.debug(f"fix agents not available: {e}")

# ── Incident state machine types ────────────────────────────────────────────────
import logging

from patchi.core import memory as mem
from patchi.core.agents.base import (
    AgentGroup,
    AgentResult,
    AgentStatus,
)
from patchi.core.agents.coordinator import Coordinator, CoordinatorProgress

_log = logging.getLogger("patchi.agents.governor")

class IncidentState(str, Enum):
    DETECTED = "detected"
    CLASSIFIED = "classified"
    TEST_SCOPED = "test_scoped"
    TEST_RUNNING = "test_running"
    TEST_COMPLETE = "test_complete"
    FIX_CANDIDATE_GENERATION = "fix_candidate_generation"
    FIX_CANDIDATE_SCORING = "fix_candidate_scoring"
    AUTO_APPLIED = "auto_applied"
    ESCALATED_TO_HUMAN = "escalated_to_human"
    REJECTED_NO_VIABLE_FIX = "rejected_no_viable_fix"
    VERIFIED_RESOLVED = "verified_resolved"
    AWAITING_HUMAN_DECISION = "awaiting_human_decision"
    FLAGGED_OPEN = "flagged_open"

    @property
    def is_terminal(self) -> bool:
        return self in (
            IncidentState.VERIFIED_RESOLVED,
            IncidentState.AWAITING_HUMAN_DECISION,
            IncidentState.FLAGGED_OPEN,
        )


@dataclass
class AuditEntry:
    prior_state: IncidentState | None
    new_state: IncidentState
    rule_id: str | None
    timestamp: str
    metadata: dict = field(default_factory=dict)


@dataclass
class Condition:
    field: str
    operator: str
    value: Any


@dataclass
class Action:
    type: str
    target: str | None = None
    next_state: str | None = None
    reason: str | None = None


@dataclass
class DispatchRule:
    rule_id: str
    applies_at_state: str
    priority: int
    conditions: list[Condition]
    action: Action
    fallback_if_no_match: bool = False


@dataclass
class Incident:
    id: str
    state: IncidentState
    control_id: str | None
    symbol_id: str | None
    technique_id: str | None
    confidence: float
    criticality: str | None = None
    check_method: str | None = None
    bug_class: str | None = None
    domain_activation_state: str | None = None
    fix_retries: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_trail: list[AuditEntry] = field(default_factory=list)


# ── Pipeline phase enum ─────────────────────────────────────────────────────────


class PipelinePhase(str, Enum):
    IDLE = "idle"
    SCAN = "scan"
    GRAPH_UPDATE = "graph_update"
    TEST_GENERATION = "test_generation"
    TEST_EXECUTION = "test_execution"
    FIX_GENERATION = "fix_generation"
    SANDBOX_REVERIFY = "sandbox_reverify"
    SCORE_SELECT = "score_select"
    COMPLETE = "complete"
    FAILED = "failed"

    @property
    def order(self) -> int:
        return _PHASE_ORDER[self]

    @property
    def next_phase(self) -> PipelinePhase | None:
        if self == PipelinePhase.FAILED:
            return None
        if self == PipelinePhase.COMPLETE:
            return None
        phases = list(PipelinePhase)
        idx = phases.index(self)
        if idx + 1 < len(phases):
            n = phases[idx + 1]
            return n if n != PipelinePhase.FAILED else None
        return None

    @classmethod
    def is_valid_transition(cls, current: PipelinePhase, target: PipelinePhase) -> bool:
        if current == PipelinePhase.IDLE:
            return target == PipelinePhase.SCAN
        if current == PipelinePhase.COMPLETE:
            return target == PipelinePhase.SCAN
        return target.order == current.order + 1


_PHASE_ORDER = {
    PipelinePhase.IDLE: 0,
    PipelinePhase.SCAN: 1,
    PipelinePhase.GRAPH_UPDATE: 2,
    PipelinePhase.TEST_GENERATION: 3,
    PipelinePhase.TEST_EXECUTION: 4,
    PipelinePhase.FIX_GENERATION: 5,
    PipelinePhase.SANDBOX_REVERIFY: 6,
    PipelinePhase.SCORE_SELECT: 7,
    PipelinePhase.COMPLETE: 8,
    PipelinePhase.FAILED: -1,
}


# ── Acceptance criteria ─────────────────────────────────────────────────────────


@dataclass
class PhaseCriteria:
    max_errors: int = 0
    max_critical_findings: int = 0
    max_high_findings: int = 10
    min_agents_run: int = 1
    require_zero_errors: bool = True


DEFAULT_CRITERIA: dict[PipelinePhase, PhaseCriteria] = {
    PipelinePhase.SCAN: PhaseCriteria(
        max_errors=5,
        max_critical_findings=200,
        max_high_findings=1000,
        min_agents_run=1,
    ),
    PipelinePhase.GRAPH_UPDATE: PhaseCriteria(
        max_errors=1,
        min_agents_run=0,
    ),
    PipelinePhase.TEST_GENERATION: PhaseCriteria(
        max_errors=3,
        min_agents_run=0,
    ),
    PipelinePhase.TEST_EXECUTION: PhaseCriteria(
        max_errors=5,
        max_critical_findings=200,
        max_high_findings=1000,
        min_agents_run=0,
    ),
    PipelinePhase.FIX_GENERATION: PhaseCriteria(
        max_errors=3,
        max_critical_findings=50,
        max_high_findings=200,
        min_agents_run=1,
    ),
    PipelinePhase.SANDBOX_REVERIFY: PhaseCriteria(
        max_errors=3,
        max_critical_findings=50,
        max_high_findings=200,
        min_agents_run=0,
    ),
    PipelinePhase.SCORE_SELECT: PhaseCriteria(
        max_errors=1,
        min_agents_run=0,
    ),
}


@dataclass
class PhaseResult:
    phase: PipelinePhase
    status: AgentStatus
    results: list[AgentResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    findings_count: int = 0
    agents_run: int = 0
    # Structured per-phase detail (e.g. verify-loop outcomes under data["verify"])
    data: dict = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == AgentStatus.DONE


# ── Governor ────────────────────────────────────────────────────────────────────


class Governor:
    """Pipeline state machine wrapping Coordinator."""

    def __init__(
        self,
        root: Path,
        on_progress: Callable[[CoordinatorProgress], None] | None = None,
        criteria: dict[PipelinePhase, PhaseCriteria] | None = None,
    ):
        self.root = root
        self.coordinator = Coordinator(root, on_progress=on_progress)
        self.criteria = criteria or DEFAULT_CRITERIA.copy()
        self._on_progress = on_progress or (lambda _: None)
        self._db_path = root / ".patchi" / "pipeline_state.db"
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS pipeline_state (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS phase_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phase TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                duration_ms INTEGER DEFAULT 0,
                findings_count INTEGER DEFAULT 0,
                agents_run INTEGER DEFAULT 0,
                errors TEXT DEFAULT ''
            );
            INSERT OR IGNORE INTO pipeline_state (key, value)
            VALUES ('current_phase', 'idle');
        """)

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def close(self) -> None:
        """Release all SQLite resources so the db file can be deleted (Windows)."""
        db_path = self._db_path
        if self._conn is not None:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._conn.execute("PRAGMA journal_mode=DELETE")
            except Exception as e:
                _log.warning("Governor.close checkpoint failed: %s", e)
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        for suffix in (".db-wal", ".db-shm"):
            try:
                Path(f"{db_path}{suffix}").unlink(missing_ok=True)
            except OSError:
                pass

    # ── Phase management ───────────────────────────────────────────────────

    @property
    def current_phase(self) -> PipelinePhase:
        conn = self._get_conn()
        cur = conn.execute("SELECT value FROM pipeline_state WHERE key = 'current_phase'")
        row = cur.fetchone()
        return PipelinePhase(row[0]) if row else PipelinePhase.IDLE

    @current_phase.setter
    def current_phase(self, phase: PipelinePhase) -> None:
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO pipeline_state (key, value) VALUES ('current_phase', ?)",
            (phase.value,),
        )

    def get_history(self, limit: int = 20) -> list[dict]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT * FROM phase_history ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = [
            {
                "id": r[0],
                "phase": r[1],
                "status": r[2],
                "timestamp": r[3],
                "duration_ms": r[4],
                "findings_count": r[5],
                "agents_run": r[6],
                "errors": r[7].split(";") if r[7] else [],
            }
            for r in cur.fetchall()
        ]
        return rows

    def _record_phase(self, result: PhaseResult) -> None:
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO phase_history (phase, status, timestamp, duration_ms, findings_count, agents_run, errors)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                result.phase.value,
                result.status.value,
                datetime.now(timezone.utc).isoformat(),
                result.duration_ms,
                result.findings_count,
                    result.agents_run,
                    ";".join(result.errors[:5]),
                ),
            )

    def _check_criteria(self, phase: PipelinePhase, results: list[AgentResult]) -> list[str]:
        """Check acceptance criteria for a phase. Returns list of violations."""
        violations: list[str] = []
        crit = self.criteria.get(phase, DEFAULT_CRITERIA[PipelinePhase.SCAN])

        errors = [r for r in results if r.status == AgentStatus.FAILED]
        if len(errors) > crit.max_errors:
            violations.append(
                f"Too many agent errors: {len(errors)} > {crit.max_errors}"
            )

        if crit.require_zero_errors and errors:
            violations.append(f"Agents failed: {', '.join(r.agent_name for r in errors)}")

        critical = sum(1 for r in results for f in r.findings if f.severity.name == "CRITICAL")
        if critical > crit.max_critical_findings:
            violations.append(
                f"Too many CRITICAL findings: {critical} > {crit.max_critical_findings}"
            )

        high = sum(1 for r in results for f in r.findings if f.severity.name == "HIGH")
        if high > crit.max_high_findings:
            violations.append(
                f"Too many HIGH findings: {high} > {crit.max_high_findings}"
            )

        if len(results) < crit.min_agents_run:
            violations.append(
                f"Not enough agents ran: {len(results)} < {crit.min_agents_run}"
            )

        return violations

    def _transition_to(
        self, target: PipelinePhase, results: list[AgentResult]
    ) -> PhaseResult:
        """Attempt to transition to the target phase. Checks criteria."""
        current = self.current_phase
        if current == PipelinePhase.FAILED:
            logger.warning("Pipeline is in FAILED state. Reset with reset_pipeline() to continue.")

        if not PipelinePhase.is_valid_transition(current, target):
            logger.warning(
                f"Invalid phase transition: {current.value} → {target.value}. "
                f"Skipping ordering check."
            )

        violations = self._check_criteria(target, results)
        duration_ms = sum(r.duration_ms for r in results)
        findings_count = sum(r.finding_count for r in results)

        if violations:
            phase_result = PhaseResult(
                phase=target,
                status=AgentStatus.FAILED,
                results=results,
                errors=violations,
                duration_ms=duration_ms,
                findings_count=findings_count,
                agents_run=len(results),
            )
            self.current_phase = PipelinePhase.FAILED
            self._record_phase(phase_result)
            return phase_result

        phase_result = PhaseResult(
            phase=target,
            status=AgentStatus.DONE,
            results=results,
            duration_ms=duration_ms,
            findings_count=findings_count,
            agents_run=len(results),
        )
        self.current_phase = target
        self._record_phase(phase_result)
        return phase_result

    # ── Graph neighborhood context (files-5 Testing Strategy §4) ──────────

    def _build_graph_neighborhood(
        self, symbol_names: list[str], radius: int = 1
    ) -> list[dict]:
        """Build scoped context for a set of symbols.

        Returns list of symbol summaries with immediate callers/callees.
        This is the graph-scoped context that replaces whole-file context
        for AI test generation and fix candidate generation.
        """
        neighborhood: list[dict] = []
        try:
            from patchi.core.brain.symbol_graph import SymbolGraph

            with SymbolGraph(self.root) as sym_graph:
                sym_graph.ensure_built()
                for sym_name in symbol_names:
                    sym = sym_graph.get_symbol(sym_name)
                    if not sym:
                        continue
                    entry = {
                        "name": sym.name,
                        "kind": sym.kind,
                        "file": sym.file,
                        "line": sym.line,
                        "is_exported": sym.is_exported,
                        "params": sym.params,
                        "docstring": sym.docstring[:120] if sym.docstring else "",
                        "callers": [],
                        "callees": [],
                    }
                    if radius >= 1:
                        for dep in sym_graph.get_dependents(sym.name, sym.file):
                            entry["callers"].append({"name": dep.name, "file": dep.file, "kind": dep.kind})
                        for dep in sym_graph.get_dependencies(sym.id):
                            entry["callees"].append({"name": dep.name, "file": dep.file, "kind": dep.kind})
                    neighborhood.append(entry)
        except Exception as e:
            logger.warning(f"build_graph_neighborhood error: {e}")
        return neighborhood

    # ── Pipeline execution ────────────────────────────────────────────────

    def run_scan(
        self, scope: list[str] | None = None, side: bool = True
    ) -> PhaseResult:
        """Phase 1: Run scanner agents."""
        logger.info(f"Pipeline phase: SCAN (scope={len(scope or [])} files, side={side})")
        results = self.coordinator.run_all_scanners(scope=scope, side=side)
        return self._transition_to(PipelinePhase.SCAN, results)

    def run_scan_deep(
        self, scope: list[str] | None = None
    ) -> PhaseResult:
        """Phase 1b: Deep scan with AI analysis."""
        logger.info(f"Pipeline phase: SCAN --deep (scope={len(scope or [])} files)")
        results = self.coordinator.run_group(AgentGroup.SCANNER, scope=scope)
        # Deep analysis via coordinator's _build_llm
        llm = self.coordinator._build_llm()
        if llm:
            try:
                from patchi.core.ai.client import call_ai

                for r in results:
                    if r.findings:
                        prompt = (
                            f"Analyze these findings for file context. "
                            f"Findings: {[f.to_dict() for f in r.findings[:5]]}"
                        )
                        analysis = call_ai(
                            self.coordinator._config,
                            "You are a security analysis assistant.",
                            prompt,
                            max_tokens=300,
                        )
                        if analysis:
                            r.data["deep_analysis"] = analysis
            except Exception as e:
                _log.warning("Governor.run_scan_deep failed: %s", e)
        return self._transition_to(PipelinePhase.SCAN, results)

    def run_test(
        self, scope: list[str] | None = None
    ) -> PhaseResult:
        """Phase 2: Run test agents."""
        logger.info(f"Pipeline phase: TEST (scope={len(scope or [])} files)")
        results = self.coordinator.run_group(AgentGroup.TEST, scope=scope)
        return self._transition_to(PipelinePhase.TEST_EXECUTION, results)

    def run_test_security(self) -> PhaseResult:
        """Phase 2b: Security-specific tests."""
        logger.info("Pipeline phase: TEST --security")
        from patchi.core.agents.base import get_agent

        agent = get_agent("SecurityTestAgent")
        if agent:
            results = self.coordinator.run_agents(["SecurityTestAgent"])
        else:
            results = []
        return self._transition_to(PipelinePhase.TEST_EXECUTION, results)

    def run_security(
        self, scope: list[str] | None = None
    ) -> PhaseResult:
        """Run security agents (part of scan phase or standalone)."""
        logger.info(f"Pipeline phase: SCAN --security (scope={len(scope or [])} files)")
        results = self.coordinator.run_group(AgentGroup.SECURITY, scope=scope)
        return PhaseResult(
            phase=PipelinePhase.SCAN,
            status=AgentStatus.DONE,
            results=results,
            duration_ms=sum(r.duration_ms for r in results),
            findings_count=sum(r.finding_count for r in results),
            agents_run=len(results),
        )

    def run_fix(
        self, dry_run: bool = False
    ) -> PhaseResult:
        """Phase: Run fix agents, then route every produced patch through the
        fix → verify → retry loop (verify_loop).

        Reuses the exact wiring ``p fix`` has: the applier is injected, each
        patch is applied and its SPECIFIC failing test re-run (retries up to
        2 with fresh failure feedback), and test-weakening patches (only test
        files changed) are flagged requires_review — never auto-applied.

        NOTE: this phase now MUTATES the working tree (applies patches) —
        previously FIX was candidate-generation only and nothing applied.
        ``dry_run=True`` is the only non-mutating path.

        Outcomes land in ``result.data["verify"]`` as lists of patch ids:
        verified / applied_unverified / review_required / rolled_back
        (``skipped`` holds error strings, not patch ids).
        """
        logger.info(f"Pipeline phase: FIX-GENERATION (dry_run={dry_run})")
        results = self.coordinator.run_group(AgentGroup.FIX, extra={"dry_run": dry_run})
        verify = self._verify_fix_patches(results, dry_run=dry_run)
        result = self._transition_to(PipelinePhase.FIX_GENERATION, results)
        result.data["verify"] = verify
        return result

    def _verify_fix_patches(self, results: list[AgentResult], dry_run: bool = False) -> dict:
        """Route produced fix patches through verify_loop (fix → verify → retry).

        Mirrors ``fix_cmd``: test-weakening guard runs first (a fix that only
        edits test files goes to human review, never auto-apply), then each
        patch is applied via ``run_verify_loop`` with a real ``PatchApplier``
        injected, which re-runs the exact failing test and retries up to 2
        times with fresh failure output. Returns a per-patch summary:

            {"verified": [ids], "applied_unverified": [ids],
             "review_required": [ids], "rolled_back": [ids], "skipped": [ids]}

        Also records ``self._last_applied_patches`` — (Patch, failing test
        file) pairs — so the REVERIFY phase can re-run those exact tests.
        """
        from patchi.core.fix.applier import PatchApplier
        from patchi.core.fix.patch import Patch
        from patchi.core.fix.verify_loop import run_verify_loop, should_flag_for_review

        summary: dict = {
            "verified": [],
            "applied_unverified": [],
            "review_required": [],
            "rolled_back": [],
            "skipped": [],
        }
        self._last_applied_patches: list[tuple[Patch, str]] = []
        if dry_run:
            return summary

        try:
            applier = PatchApplier(self.root)
        except Exception as e:
            logger.warning(f"FIX verify: PatchApplier unavailable, skipping apply: {e}")
            summary["skipped"].append(f"PatchApplier: {e}")
            return summary
        config = self.config or {}
        brain = self.brain or {}

        for r in results:
            for patch_dict in r.data.get("patches", []):
                try:
                    patch = Patch.from_dict(patch_dict)
                except Exception as e:
                    summary["skipped"].append(str(e))
                    continue

                # Test-weakening guard — flag BEFORE the loop so AUTOPILOT can't
                # slip a test-only fix past the apply path.
                if should_flag_for_review(patch):
                    patch.requires_review = True
                    summary["review_required"].append(patch.id)
                    self._last_applied_patches.append((patch, ""))
                    continue

                try:
                    outcome = run_verify_loop(
                        patch,
                        root=self.root,
                        config=config,
                        brain=brain,
                        applier=applier,
                    )
                except Exception as e:
                    summary["rolled_back"].append(patch.id)
                    self._last_applied_patches.append((patch, ""))
                    logger.warning(f"verify loop failed for {patch.id}: {e}")
                    continue

                done = outcome.patch or patch
                test_file = (done.source_finding or {}).get("file", "")
                if outcome.review_required:
                    summary["review_required"].append(done.id)
                elif outcome.applied and outcome.verified:
                    summary["verified"].append(done.id)
                elif outcome.applied:
                    summary["applied_unverified"].append(done.id)
                else:
                    summary["rolled_back"].append(done.id)
                self._last_applied_patches.append((done, test_file))

        logger.info(
            f"FIX verify: {len(summary['verified'])} verified, "
            f"{len(summary['applied_unverified'])} applied-unverified, "
            f"{len(summary['review_required'])} review-required, "
            f"{len(summary['rolled_back'])} rolled back"
        )
        return summary

    def _recheck_applied_patches(self) -> dict:
        """REVERIFY: re-run the SPECIFIC failing test of each patch that the
        FIX phase applied/verified — not the whole test group.

        Returns {"rechecked": n, "passed": [ids], "regressed": [ids],
        "unrunnable": [ids]} where regressed means a previously-verified test
        now fails after later phases touched the tree.
        """
        from patchi.core.fix.verify_loop import recheck_test_file

        report: dict = {"rechecked": 0, "passed": [], "regressed": [], "unrunnable": []}
        for patch, test_file in getattr(self, "_last_applied_patches", []):
            if not test_file:
                continue
            check = recheck_test_file(self.root, test_file)
            report["rechecked"] += 1
            if check.get("passed") is True:
                report["passed"].append(patch.id)
            elif check.get("passed") is False:
                report["regressed"].append(patch.id)
            else:
                report["unrunnable"].append(patch.id)
        return report

    def run_fix_security(self) -> PhaseResult:
        """Phase: Security-specific fixes."""
        logger.info("Pipeline phase: FIX-GENERATION --security")
        from patchi.core.agents.base import get_agent

        agent = get_agent("SecurityFixer")
        if agent:
            results = self.coordinator.run_agents(["SecurityFixer"])
        else:
            results = []
        return self._transition_to(PipelinePhase.FIX_GENERATION, results)

    def run_reverify(self) -> PhaseResult:
        """Phase 4: Re-verify by re-running scan agents and checking fixes.

        On top of the loop-back scan, re-runs the SPECIFIC failing tests of
        patches applied in the FIX phase (via verify_loop.recheck_test_file) so
        a regression in an applied fix fails the phase, not just "some findings
        remain". Recheck results land in ``result.data["reverify"]``.
        """
        logger.info("Pipeline phase: REVERIFY")
        scan_results = self.coordinator.run_all_scanners()
        security_results = self.coordinator.run_group(AgentGroup.SECURITY)

        all_results = scan_results + security_results
        total_findings = sum(r.finding_count for r in all_results)
        reverify = self._recheck_applied_patches()

        crit = self.criteria.get(PipelinePhase.SANDBOX_REVERIFY, DEFAULT_CRITERIA[PipelinePhase.SANDBOX_REVERIFY])
        violations: list[str] = []
        if total_findings > crit.max_critical_findings:
            violations.append(
                f"Re-verify failed: {total_findings} findings remain"
            )
        if reverify["regressed"]:
            violations.append(
                f"Re-verify failed: {len(reverify['regressed'])} previously-verified "
                f"test(s) regressed: {', '.join(reverify['regressed'])}"
            )

        if violations:
            phase_result = PhaseResult(
                phase=PipelinePhase.SANDBOX_REVERIFY,
                status=AgentStatus.FAILED,
                results=all_results,
                errors=violations,
                duration_ms=sum(r.duration_ms for r in all_results),
                findings_count=total_findings,
                agents_run=len(all_results),
                data={"reverify": reverify},
            )
            self._record_phase(phase_result)
            return phase_result

        phase_result = PhaseResult(
            phase=PipelinePhase.SANDBOX_REVERIFY,
            status=AgentStatus.DONE,
            results=all_results,
            duration_ms=sum(r.duration_ms for r in all_results),
            findings_count=total_findings,
            agents_run=len(all_results),
            data={"reverify": reverify},
        )
        self._record_phase(phase_result)
        self.current_phase = PipelinePhase.COMPLETE
        return phase_result

    # ── New v2 phases ──────────────────────────────────────────────────────

    def run_graph_update(self) -> PhaseResult:
        """Phase 2: Build or incrementally update the SymbolGraph.

        The full graph is built HERE — during the SCAN/GRAPH_UPDATE phase — so
        later FIX/TEST phases never pay a full tree-sitter parse latency spike
        through the lazy ensure_built() query path.

        Uses the graph_diff from BrainReport to identify changed files and
        apply SymbolGraph.patch() incrementally; when no diff exists (fresh
        project, no prior scan), it falls back to a full build_from_root().
        """
        start = time.monotonic()
        logger.info("Pipeline phase: GRAPH_UPDATE")
        errors: list[str] = []
        changed_paths: list[Path] = []
        built = False

        try:
            brain_mem = mem.get_brain(self.root)
            graph_diff = brain_mem.get("graph_diff", {})

            for f in graph_diff.get("new_files", []):
                p = self.root / f
                if p.exists():
                    changed_paths.append(p)
            for f in graph_diff.get("removed_files", []):
                p = self.root / f
                if p.exists():
                    changed_paths.append(p)

            try:
                from patchi.core.brain.symbol_graph import SymbolGraph

                with SymbolGraph(self.root) as sym_graph:
                    if changed_paths:
                        # Build a base graph if the DB is empty, then apply
                        # the incremental patch from the scan diff.
                        sym_graph.ensure_built()
                        diff = sym_graph.patch(changed_paths)
                        built = True
                        logger.info(f"Graph update: patched {diff.summary()}")
                    else:
                        # No diff — ensure the full graph exists now so
                        # FIX/TEST phases never trigger the parse spike later.
                        # ensure_built() does a full build_from_root when the
                        # DB is empty (fresh project) and is a cheap no-op on
                        # re-runs where the graph is already populated.
                        count = sym_graph.ensure_built()
                        built = True
                        logger.info(f"Graph update: graph ensured ({count} symbols)")
            except Exception as e:
                errors.append(f"SymbolGraph build/patch failed: {e}")
        except Exception as e:
            errors.append(f"Graph update failed: {e}")

        duration_ms = int((time.monotonic() - start) * 1000)
        result = PhaseResult(
            phase=PipelinePhase.GRAPH_UPDATE,
            status=AgentStatus.DONE if not errors else AgentStatus.FAILED,
            errors=errors,
            duration_ms=duration_ms,
            agents_run=1 if built else 0,
        )
        self._record_phase(result)
        self.current_phase = PipelinePhase.GRAPH_UPDATE
        return result

    def _affected_symbols_from_scan(self) -> list[str]:
        """Extract affected symbol names from the last scan's graph diff."""
        symbols: list[str] = []
        try:
            brain_mem = mem.get_brain(self.root)
            graph_diff = brain_mem.get("graph_diff", {})

            for f in graph_diff.get("new_files", []):
                try:
                    from patchi.core.brain.symbol_graph import SymbolGraph

                    with SymbolGraph(self.root) as sym_graph:
                        sym_graph.ensure_built()
                        for sym in sym_graph.get_symbols_in_file(f):
                            symbols.append(sym.name)
                except Exception as e:
                    logger.debug(f"SymbolGraph error for {f}: {e}")
        except Exception as e:
            logger.debug(f"get_symbols_in_file error: {e}")
        return symbols

    def run_test_generation(self) -> PhaseResult:
        """Phase 3: Graph-scoped test generation.

        Uses symbol neighborhood context instead of whole-file context.
        This directly addresses the 11-vs-1 hallucination reduction finding
        from Testing Strategy §4.
        """
        start = time.monotonic()
        logger.info("Pipeline phase: TEST_GENERATION")
        errors: list[str] = []

        affected_symbols = self._affected_symbols_from_scan()
        if not affected_symbols:
            logger.info("Test generation: no affected symbols, skipping")
            result = PhaseResult(
                phase=PipelinePhase.TEST_GENERATION,
                status=AgentStatus.DONE,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            self._record_phase(result)
            return result

        # Build graph-scoped context
        neighborhood = self._build_graph_neighborhood(affected_symbols, radius=1)
        if not neighborhood:
            logger.info("Test generation: no graph context, skipping")
            result = PhaseResult(
                phase=PipelinePhase.TEST_GENERATION,
                status=AgentStatus.DONE,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            self._record_phase(result)
            return result

        # Generate tests scoped to affected symbols
        try:
            from patchi.core.agents.base import get_agent

            agent = get_agent("SecurityTestAgent")
            if agent:
                extra = {
                    "graph_neighborhood": neighborhood,
                    "affected_symbols": affected_symbols,
                    "generation_mode": "scoped",
                }
                agent_results = self.coordinator.run_agents(
                    ["SecurityTestAgent"], extra=extra
                )
            else:
                # Fallback: use test agent if available
                agent_results = self.coordinator.run_group(
                    AgentGroup.TEST,
                    extra={"graph_neighborhood": neighborhood, "generation_mode": "scoped"},
                )
        except Exception as e:
            errors.append(f"Test generation failed: {e}")
            agent_results = []

        duration_ms = int((time.monotonic() - start) * 1000)
        findings_count = sum(r.finding_count for r in agent_results)

        result = PhaseResult(
            phase=PipelinePhase.TEST_GENERATION,
            status=AgentStatus.DONE if not errors else AgentStatus.FAILED,
            results=agent_results,
            errors=errors,
            duration_ms=duration_ms,
            findings_count=findings_count,
            agents_run=len(agent_results),
        )
        self._record_phase(result)
        self.current_phase = PipelinePhase.TEST_GENERATION
        return result

    def run_fix_generation(self, dry_run: bool = False) -> PhaseResult:
        """Phase 5: Fix candidate generation with multiple candidates.

        Deterministic autofix first (ESLint --fix, Semgrep autofix, etc.).
        LLM candidates for residual cases. Multiple candidates generated
        and scored against the composite (tests pass, blast-radius delta,
        no new scan findings).
        """
        start = time.monotonic()
        logger.info(f"Pipeline phase: FIX_GENERATION (dry_run={dry_run})")

        # Build graph-scoped context for fix agents
        affected_symbols = self._affected_symbols_from_scan()
        extra: dict = {"dry_run": dry_run}
        if affected_symbols:
            neighborhood = self._build_graph_neighborhood(affected_symbols, radius=1)
            extra["graph_neighborhood"] = neighborhood
            extra["affected_symbols"] = affected_symbols

        # Run fix agents with graph-scoped context
        results = self.coordinator.run_group(AgentGroup.FIX, extra=extra)

        # fix → verify → retry loop over every produced patch (never weaken
        # tests): apply with the applier injected, re-run the specific failing
        # test, retry up to 2 with fresh failure feedback, and flag test-only
        # patches for human review. Outcomes land in result.data["verify"].
        verify = self._verify_fix_patches(results, dry_run=dry_run)

        # Score candidates (store for SCORE_SELECT phase)
        scored_candidates = []
        for r in results:
            candidate = {
                "agent_name": r.agent_name,
                "status": r.status.value,
                "findings": r.finding_count,
                "duration_ms": r.duration_ms,
                "score": self._score_fix_candidate(r),
            }
            scored_candidates.append(candidate)
        self._last_candidates = scored_candidates
        self._last_fix_results = results

        duration_ms = int((time.monotonic() - start) * 1000)
        result = self._transition_to(PipelinePhase.FIX_GENERATION, results)
        result.data["verify"] = verify
        result.duration_ms = duration_ms
        return result

    def _score_fix_candidate(self, result: AgentResult) -> float:
        """Score a fix candidate on 0-1 scale.

        Factors:
        - Agent completed without errors (0.4)
        - Finding count (lower = better, 0.3)
        - Has fix data (0.2)
        - Fast runtime (0.1)
        """
        score = 0.0
        if result.status == AgentStatus.DONE:
            score += 0.4
        score += max(0, 0.3 - (result.finding_count * 0.02))
        if result.data:
            score += 0.2
        score += max(0, 0.1 - (result.duration_ms * 0.00001))
        return min(1.0, max(0.0, score))

    def run_sandbox_reverify(self) -> PhaseResult:
        """Phase 6: Sandbox reverification with loop-back scan + test re-run.

        For each fix candidate:
        1. Re-run the scoped test set from TEST_EXECUTION
        2. Re-run the scanner on the candidate diff
        3. Check for new findings introduced by the fix

        Uses git worktree or temp directory as sandbox.
        """
        start = time.monotonic()
        logger.info("Pipeline phase: SANDBOX_REVERIFY")
        errors: list[str] = []
        all_results: list[AgentResult] = []

        candidates = getattr(self, "_last_candidates", [])
        fix_results = getattr(self, "_last_fix_results", [])

        if not fix_results:
            logger.info("Sandbox reverify: no fix candidates to verify")
            result = PhaseResult(
                phase=PipelinePhase.SANDBOX_REVERIFY,
                status=AgentStatus.DONE,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            self._record_phase(result)
            return result

        for i, (candidate, fix_res) in enumerate(zip(candidates, fix_results)):
            logger.info(f"Reverifying candidate {i+1}/{len(candidates)}: {candidate['agent_name']}")

            # Re-run scanner agents on the working tree
            try:
                scan_results = self.coordinator.run_all_scanners()
                all_results.extend(scan_results)
            except Exception as e:
                errors.append(f"Re-scan for {candidate['agent_name']} failed: {e}")

            # Re-run test agents
            try:
                test_results = self.coordinator.run_group(AgentGroup.TEST)
                all_results.extend(test_results)
            except Exception as e:
                errors.append(f"Re-test for {candidate['agent_name']} failed: {e}")

        # Check for newly introduced findings
        total_findings = sum(r.finding_count for r in all_results)
        if total_findings > 0:
            logger.warning(f"Sandbox reverify: {total_findings} findings remain after fix")

        # Re-run the SPECIFIC failing tests of patches applied in FIX_GENERATION
        # (verify_loop.recheck_test_file) — a regression there fails the phase.
        reverify = self._recheck_applied_patches()
        if reverify["regressed"]:
            errors.append(
                f"Sandbox reverify: {len(reverify['regressed'])} previously-verified "
                f"test(s) regressed: {', '.join(reverify['regressed'])}"
            )

        duration_ms = int((time.monotonic() - start) * 1000)
        result = PhaseResult(
            phase=PipelinePhase.SANDBOX_REVERIFY,
            status=AgentStatus.DONE,
            results=all_results,
            errors=errors,
            duration_ms=duration_ms,
            findings_count=total_findings,
            agents_run=len(all_results),
            data={"reverify": reverify},
        )

        violations = self._check_criteria(PipelinePhase.SANDBOX_REVERIFY, all_results)
        if violations:
            result.status = AgentStatus.FAILED
            result.errors.extend(violations)

        self._record_phase(result)
        if result.status == AgentStatus.DONE:
            self.current_phase = PipelinePhase.SANDBOX_REVERIFY
        return result

    def run_score_select(self) -> PhaseResult:
        """Phase 7: Composite scoring → select winner or escalate to human.

        Compares all fix candidates, selects the best-scoring one,
        logs the decision with all candidate scores for audit trail.
        If no candidate passes all gates, escalates to human review.
        """
        start = time.monotonic()
        logger.info("Pipeline phase: SCORE_SELECT")
        errors: list[str] = []

        candidates = getattr(self, "_last_candidates", [])
        fix_results = getattr(self, "_last_fix_results", [])

        if not candidates:
            errors.append("No fix candidates to score")
            result = PhaseResult(
                phase=PipelinePhase.SCORE_SELECT,
                status=AgentStatus.FAILED,
                errors=errors,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            self._record_phase(result)
            return result

        # Sort by score descending
        ranked = sorted(
            zip(candidates, fix_results),
            key=lambda x: x[0]["score"],
            reverse=True,
        )

        winners: list[dict] = []
        for cand, res in ranked:
            decision = self._select_candidate(cand, res)
            entry = {
                "candidate": cand,
                "decision": decision["action"],
                "reason": decision["reason"],
            }
            winners.append(entry)

        # Log all candidates and decision
        logger.info(f"Score-select: {len(candidates)} candidates evaluated")
        for w in winners:
            logger.info(f"  {w['candidate']['agent_name']}: score={w['candidate']['score']:.2f} → {w['decision']}")

        self._last_selection = winners

        duration_ms = int((time.monotonic() - start) * 1000)

        # If any candidate passes, phase passes
        any_pass = any(w["decision"] == "auto_apply" for w in winners)
        result = PhaseResult(
            phase=PipelinePhase.SCORE_SELECT,
            status=AgentStatus.DONE if any_pass or not errors else AgentStatus.FAILED,
            errors=errors,
            duration_ms=duration_ms,
            agents_run=len(candidates),
        )
        if any_pass:
            self.current_phase = PipelinePhase.COMPLETE
        self._record_phase(result)
        return result

    def _select_candidate(self, candidate: dict, result: AgentResult) -> dict:
        """Decide whether a candidate is auto-applied or escalated.

        Returns {"action": "auto_apply"|"escalate"|"discard", "reason": str}.
        """
        score = candidate["score"]

        # Gates
        if result.status != AgentStatus.DONE:
            return {"action": "discard", "reason": f"Agent failed: {result.status.value}"}

        if candidate["findings"] > 0:
            return {"action": "escalate", "reason": f"{candidate['findings']} findings remain"}

        # Score thresholds
        if score >= 0.8:
            return {"action": "auto_apply", "reason": f"Score {score:.2f} ≥ 0.8, all gates passed"}
        if score >= 0.5:
            return {"action": "escalate", "reason": f"Score {score:.2f} moderate, needs human review"}

        return {"action": "discard", "reason": f"Score {score:.2f} too low"}

    # ── Full pipeline runners ─────────────────────────────────────────────

    def run_full_pipeline(
        self,
        scope: list[str] | None = None,
        dry_run: bool = False,
    ) -> list[PhaseResult]:
        """Run the full SCAN → TEST → FIX → REVERIFY pipeline sequentially."""
        phases: list[PhaseResult] = []

        scan_result = self.run_scan(scope=scope)
        phases.append(scan_result)
        if not scan_result.passed:
            logger.error("SCAN phase failed, aborting pipeline")
            return phases

        test_result = self.run_test()
        phases.append(test_result)
        if not test_result.passed:
            logger.warning("TEST phase has issues, proceeding with caution")

        fix_result = self.run_fix(dry_run=dry_run)
        phases.append(fix_result)
        if not fix_result.passed:
            logger.warning("FIX phase has issues")

        reverify_result = self.run_reverify()
        phases.append(reverify_result)

        return phases

    def run_full_pipeline_v2(
        self,
        scope: list[str] | None = None,
        dry_run: bool = False,
    ) -> list[PhaseResult]:
        """Run the full 7-step pipeline.

        SCAN → GRAPH_UPDATE → TEST_GENERATION → TEST_EXECUTION
        → FIX_GENERATION → SANDBOX_REVERIFY → SCORE_SELECT
        """
        phases: list[PhaseResult] = []

        # 1. SCAN
        scan_result = self.run_scan(scope=scope)
        phases.append(scan_result)
        if not scan_result.passed:
            logger.error("SCAN failed, aborting v2 pipeline")
            self.current_phase = PipelinePhase.FAILED
            return phases

        # 2. GRAPH_UPDATE — incremental SymbolGraph patch
        graph_result = self.run_graph_update()
        phases.append(graph_result)

        # 3. TEST_GENERATION — graph-scoped
        test_gen_result = self.run_test_generation()
        phases.append(test_gen_result)

        # 4. TEST_EXECUTION — run test agents (existing)
        test_exec_result = self.run_test()
        phases.append(test_exec_result)
        if not test_exec_result.passed:
            logger.warning("TEST_EXECUTION has issues, proceeding with caution")

        # 5. FIX_GENERATION — multiple candidates, deterministic first
        fix_gen_result = self.run_fix_generation(dry_run=dry_run)
        phases.append(fix_gen_result)
        if not fix_gen_result.passed:
            logger.warning("FIX_GENERATION has issues")

        # 6. SANDBOX_REVERIFY — loop-back scan + test re-run
        reverify_result = self.run_sandbox_reverify()
        phases.append(reverify_result)

        # 7. SCORE_SELECT — composite score → select or escalate
        select_result = self.run_score_select()
        phases.append(select_result)

        return phases

    # ── State management ──────────────────────────────────────────────────

    def reset_pipeline(self) -> None:
        """Reset pipeline state back to IDLE."""
        self.current_phase = PipelinePhase.IDLE
        logger.info("Pipeline reset to IDLE")

    def status(self) -> dict:
        """Return current pipeline status as a dict."""
        phase = self.current_phase
        history = self.get_history(5)
        return {
            "current_phase": phase.value,
            "phase_order": phase.order,
            "next_phase": phase.next_phase.value if phase.next_phase else None,
            "is_running": phase not in (PipelinePhase.IDLE, PipelinePhase.COMPLETE, PipelinePhase.FAILED),
            "recent_history": history,
        }

    # ── Coordinator passthrough ───────────────────────────────────────────

    @property
    def config(self) -> dict:
        return getattr(self.coordinator, "_config", {})

    @property
    def brain(self) -> dict:
        return getattr(self.coordinator, "_brain", {})

    def run_agents(
        self, agent_names: list[str], scope: list[str] | None = None
    ) -> list[AgentResult]:
        """Passthrough to Coordinator.run_agents."""
        return self.coordinator.run_agents(agent_names, scope=scope)

    def run_group(
        self, group: AgentGroup, scope: list[str] | None = None
    ) -> list[AgentResult]:
        """Passthrough to Coordinator.run_group."""
        return self.coordinator.run_group(group, scope=scope)


# ── GovernorEngine ──────────────────────────────────────────────────────────────


class GovernorEngine:
    """Incident-based state machine wrapping Governor.

    Manages incidents (create, transition, query), loads dispatch rules,
    evaluates escalation rules (spec §3), tracks fix retries and agent dispatch rate.

    Additive — wraps Governor, does not replace it. The existing Governor
    and run_full_pipeline_v2() continue working unchanged.
    """

    def __init__(
        self,
        root: Path,
        on_progress: Callable[[CoordinatorProgress], None] | None = None,
        criteria: dict[PipelinePhase, PhaseCriteria] | None = None,
        rules_dir: Path | str | None = None,
    ):
        self.root = Path(root)
        self.governor = Governor(root, on_progress=on_progress, criteria=criteria)
        self._on_progress = on_progress or (lambda _: None)
        self._rules_dir = Path(rules_dir) if rules_dir else self.root / ".patchi" / "rules"
        self._incidents: dict[str, Incident] = {}
        self._rules: list[DispatchRule] = []
        self._dispatch_timestamps: deque[float] = deque()

        # Configurable thresholds (spec §4 reference table)
        self._conf_threshold: float = 0.4
        self._auto_apply_threshold: float = 0.75
        self._max_fix_retries: int = 3
        self._max_dispatches_per_window: int = 50
        self._dispatch_window_seconds: int = 60

        self._load_rules()
        self._init_db()

    # ── Database schema extension ─────────────────────────────────────────

    def _init_db(self) -> None:
        """Extend the existing pipeline_state.db with incident tables."""
        try:
            conn = self.governor._get_conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    control_id TEXT,
                    symbol_id TEXT,
                    technique_id TEXT,
                    confidence REAL DEFAULT 0.0,
                    criticality TEXT,
                    check_method TEXT,
                    bug_class TEXT,
                    domain_activation_state TEXT,
                    fix_retries INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incident_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    prior_state TEXT,
                    new_state TEXT NOT NULL,
                    rule_id TEXT,
                    timestamp TEXT NOT NULL,
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                );
                CREATE TABLE IF NOT EXISTS dispatch_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT,
                    rule_id TEXT,
                    target_agent TEXT,
                    timestamp TEXT NOT NULL
                );
            """)
        except Exception as e:
            logger.warning(f"Could not extend schema for incidents: {e}")

    # ── Rule loading (file-based YAML, spec §2) ───────────────────────────

    def _load_rules(self) -> None:
        """Load dispatch rules from YAML files in .patchi/rules/."""
        if not self._rules_dir.exists():
            logger.info(f"No rules directory at {self._rules_dir}, skipping")
            return

        loaded = 0
        for yaml_path in sorted(self._rules_dir.glob("**/*.yaml")):
            try:
                with open(yaml_path, "r") as f:
                    data = yaml.safe_load(f)
                if not data:
                    continue

                conditions = [
                    Condition(field=c["field"], operator=c["operator"], value=c["value"])
                    for c in data.get("conditions", [])
                ]

                action_raw = data.get("action", {})
                action = Action(
                    type=action_raw.get("type", "transition"),
                    target=action_raw.get("target"),
                    next_state=action_raw.get("next_state"),
                    reason=action_raw.get("reason"),
                )

                rule = DispatchRule(
                    rule_id=data.get("rule_id", yaml_path.stem),
                    applies_at_state=data.get("applies_at_state", "DETECTED"),
                    priority=data.get("priority", 100),
                    conditions=conditions,
                    action=action,
                    fallback_if_no_match=data.get("fallback_if_no_match", False),
                )
                self._rules.append(rule)
                loaded += 1
            except Exception as e:
                logger.error(f"Failed to load rule {yaml_path}: {e}")

        self._rules.sort(key=lambda r: r.priority)
        logger.info(f"Loaded {loaded} dispatch rules from {self._rules_dir}")

    # ── Incident CRUD ─────────────────────────────────────────────────────

    def create_incident(
        self,
        control_id: str | None = None,
        symbol_id: str | None = None,
        technique_id: str | None = None,
        confidence: float = 0.0,
        criticality: str | None = None,
        check_method: str | None = None,
        bug_class: str | None = None,
        domain_activation_state: str | None = None,
        finding_dict: dict | None = None,
    ) -> Incident:
        """Create a new incident, optionally from a finding dict."""
        if finding_dict:
            control_id = control_id or finding_dict.get("control_id")
            symbol_id = symbol_id or finding_dict.get("symbol_id") or finding_dict.get("affected_node", {}).get("symbol")
            technique_id = technique_id or finding_dict.get("technique_id")
            confidence = confidence if confidence else finding_dict.get("confidence", 0.0)
            criticality = criticality or finding_dict.get("affected_node", {}).get("criticality") or finding_dict.get("criticality")
            check_method = check_method or finding_dict.get("check_method")
            bug_class = bug_class or finding_dict.get("bug_class")
            domain_activation_state = domain_activation_state or finding_dict.get("domain_activation_state")

        incident_id = f"INC-{int(time.time() * 1000)}-{len(self._incidents) + 1}"
        now = datetime.now(timezone.utc).isoformat()

        incident = Incident(
            id=incident_id,
            state=IncidentState.DETECTED,
            control_id=control_id,
            symbol_id=symbol_id,
            technique_id=technique_id,
            confidence=confidence,
            criticality=criticality,
            check_method=check_method,
            bug_class=bug_class,
            domain_activation_state=domain_activation_state,
            created_at=now,
            updated_at=now,
            audit_trail=[
                AuditEntry(
                    prior_state=None,
                    new_state=IncidentState.DETECTED,
                    rule_id="system",
                    timestamp=now,
                    metadata={"source": "finding_ingested"},
                )
            ],
        )
        self._incidents[incident_id] = incident
        self._persist_incident(incident)
        logger.info(f"Created incident {incident_id} (technique={technique_id}, confidence={confidence})")
        return incident

    def get_incident(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def get_incidents(self, state: IncidentState | None = None) -> list[Incident]:
        if state is None:
            return list(self._incidents.values())
        return [i for i in self._incidents.values() if i.state == state]

    def _persist_incident(self, incident: Incident) -> None:
        try:
            conn = self.governor._get_conn()
            conn.execute(
                """INSERT OR REPLACE INTO incidents
                   (id, state, control_id, symbol_id, technique_id, confidence,
                    criticality, check_method, bug_class, domain_activation_state,
                    fix_retries, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident.id, incident.state.value, incident.control_id,
                    incident.symbol_id, incident.technique_id, incident.confidence,
                    incident.criticality, incident.check_method, incident.bug_class,
                    incident.domain_activation_state, incident.fix_retries,
                    incident.created_at, incident.updated_at,
                ),
            )
        except Exception as e:
            logger.warning(f"Failed to persist incident {incident.id}: {e}")

    def _persist_audit_entry(self, incident_id: str, entry: AuditEntry) -> None:
        try:
            conn = self.governor._get_conn()
            conn.execute(
                """INSERT INTO incident_audit (incident_id, prior_state, new_state, rule_id, timestamp, metadata)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    incident_id,
                    entry.prior_state.value if entry.prior_state else None,
                    entry.new_state.value,
                    entry.rule_id,
                    entry.timestamp,
                    str(entry.metadata),
                ),
            )
        except Exception as e:
            logger.warning(f"Failed to persist audit entry: {e}")

    # ── State transitions ─────────────────────────────────────────────────

    def transition_incident(
        self,
        incident_id: str,
        new_state: IncidentState,
        rule_id: str | None = None,
        metadata: dict | None = None,
    ) -> Incident | None:
        """Transition an incident to a new state. Logs the transition to the audit trail."""
        incident = self._incidents.get(incident_id)
        if not incident:
            logger.warning(f"Incident {incident_id} not found")
            return None

        prior_state = incident.state
        now = datetime.now(timezone.utc).isoformat()

        entry = AuditEntry(
            prior_state=prior_state,
            new_state=new_state,
            rule_id=rule_id,
            timestamp=now,
            metadata=metadata or {},
        )

        incident.state = new_state
        incident.updated_at = now
        incident.audit_trail.append(entry)

        self._persist_incident(incident)
        self._persist_audit_entry(incident_id, entry)

        logger.debug(f"Incident {incident_id}: {prior_state.value} → {new_state.value} (rule={rule_id})")
        return incident

    # ── Dispatch rule evaluation (spec §2, first-match-wins) ──────────────

    def _resolve_field(self, incident: Incident, field_path: str) -> Any:
        """Resolve a dotted field path against an incident (e.g. finding.technique_id)."""
        if field_path.startswith("finding."):
            key = field_path[len("finding."):]
            mapping = {
                "technique_id": incident.technique_id,
                "confidence": incident.confidence,
                "criticality": incident.criticality,
                "check_method": incident.check_method,
                "bug_class": incident.bug_class,
                "domain_activation_state": incident.domain_activation_state,
                "control_id": incident.control_id,
                "symbol_id": incident.symbol_id,
            }
            return mapping.get(key)

        if field_path.startswith("best_candidate."):
            key = field_path[len("best_candidate."):]
            return getattr(self, f"_candidate_{key}", None)

        return getattr(incident, field_path, None)

    def _evaluate_conditions(self, incident: Incident, conditions: list[Condition]) -> bool:
        for cond in conditions:
            value = self._resolve_field(incident, cond.field)

            if cond.operator == "in":
                if isinstance(value, list):
                    if not any(v in cond.value for v in value):
                        return False
                elif value not in cond.value:
                    return False
            elif cond.operator == ">=":
                if not (value is not None and value >= cond.value):
                    return False
            elif cond.operator == "<=":
                if not (value is not None and value <= cond.value):
                    return False
            elif cond.operator == ">":
                if not (value is not None and value > cond.value):
                    return False
            elif cond.operator == "<":
                if not (value is not None and value < cond.value):
                    return False
            elif cond.operator == "==":
                if value != cond.value:
                    return False
            elif cond.operator == "!=":
                if value == cond.value:
                    return False
            else:
                logger.warning(f"Unknown condition operator: {cond.operator}")
                return False
        return True

    def evaluate_dispatch_rules(
        self, incident: Incident, at_state: IncidentState | None = None
    ) -> DispatchRule | None:
        """First-match-wins rule evaluation. Returns the first matching rule or None."""
        state = at_state or incident.state
        for rule in self._rules:
            if rule.applies_at_state != state.value:
                continue
            if self._evaluate_conditions(incident, rule.conditions):
                logger.info(f"Rule {rule.rule_id} matched incident {incident.id}")
                return rule
        return None

    # ── Escalation rules: §3.1 Hard triggers ──────────────────────────────

    def check_hard_escalation_triggers(self, incident: Incident) -> str | None:
        """§3.1 — unconditional, score-independent triggers."""
        # criticality in [auth, secrets, payment, data-write] at FIX_CANDIDATE_SCORING
        if incident.state == IncidentState.FIX_CANDIDATE_SCORING:
            if incident.criticality in ("auth", "secrets", "payment", "data-write"):
                return "hard-trigger-criticality"

        # check_method == "manual-review" at CLASSIFIED
        if incident.state == IncidentState.CLASSIFIED:
            if incident.check_method == "manual-review":
                return "hard-trigger-manual-review"

        # bug_class == "semantic-mismatch" at TEST_COMPLETE
        if incident.state == IncidentState.TEST_COMPLETE:
            if incident.bug_class == "semantic-mismatch":
                return "hard-trigger-semantic-mismatch"

        # domain_activation_state == "unclear" at CLASSIFIED
        if incident.state == IncidentState.CLASSIFIED:
            if incident.domain_activation_state == "unclear":
                return "hard-trigger-unclear-domain"

        return None

    # ── Escalation rules: §3.2 Score-based ────────────────────────────────

    def check_score_escalation(self, incident: Incident, best_score: float | None = None) -> str | None:
        """§3.2 — composite score below configurable threshold."""
        if incident.state != IncidentState.FIX_CANDIDATE_SCORING:
            return None
        if best_score is not None and best_score < self._auto_apply_threshold:
            return f"score-below-threshold-{best_score:.2f}"
        return None

    # ── Escalation rules: §3.3 Rate-limiting / loop prevention ────────────

    def check_rate_limiting(self, incident: Incident) -> str | None:
        """§3.3 — fix-retry loops and dispatch-rate ceilings."""
        if incident.state in (
            IncidentState.FIX_CANDIDATE_GENERATION,
            IncidentState.FIX_CANDIDATE_SCORING,
        ):
            if incident.fix_retries >= self._max_fix_retries:
                return "max-fix-retries-exceeded"

        now = time.time()
        while self._dispatch_timestamps and self._dispatch_timestamps[0] < now - self._dispatch_window_seconds:
            self._dispatch_timestamps.popleft()

        if len(self._dispatch_timestamps) >= self._max_dispatches_per_window:
            return "dispatch-rate-exceeded"

        return None

    # ── Combined escalation check ─────────────────────────────────────────

    def check_escalation(self, incident: Incident, best_score: float | None = None) -> str | None:
        """Evaluate all escalation rules in order. Returns the first reason or None."""
        hard = self.check_hard_escalation_triggers(incident)
        if hard:
            return hard

        score = self.check_score_escalation(incident, best_score)
        if score:
            return score

        rate = self.check_rate_limiting(incident)
        if rate:
            return rate

        return None

    # ── Dispatch rate tracking ────────────────────────────────────────────

    def record_dispatch(self, incident_id: str | None = None, rule_id: str | None = None) -> None:
        now = time.time()
        self._dispatch_timestamps.append(now)
        try:
            conn = self.governor._get_conn()
            conn.execute(
                """INSERT INTO dispatch_log (incident_id, rule_id, target_agent, timestamp)
                   VALUES (?, ?, ?, ?)""",
                (incident_id, rule_id, None, datetime.now(timezone.utc).isoformat()),
            )
        except Exception as e:
            logger.warning(f"Failed to log dispatch for {incident_id}: {e}")

    def can_dispatch(self) -> bool:
        """Check dispatch rate — True if under the ceiling."""
        now = time.time()
        while self._dispatch_timestamps and self._dispatch_timestamps[0] < now - self._dispatch_window_seconds:
            self._dispatch_timestamps.popleft()
        return len(self._dispatch_timestamps) < self._max_dispatches_per_window

    # ── Pipeline integration ──────────────────────────────────────────────

    @staticmethod
    def _map_phase_to_incident_state(phase: PipelinePhase) -> IncidentState | None:
        mapping = {
            PipelinePhase.SCAN: IncidentState.CLASSIFIED,
            PipelinePhase.GRAPH_UPDATE: IncidentState.CLASSIFIED,
            PipelinePhase.TEST_GENERATION: IncidentState.TEST_SCOPED,
            PipelinePhase.TEST_EXECUTION: IncidentState.TEST_COMPLETE,
            PipelinePhase.FIX_GENERATION: IncidentState.FIX_CANDIDATE_GENERATION,
            PipelinePhase.SANDBOX_REVERIFY: None,
            PipelinePhase.SCORE_SELECT: IncidentState.FIX_CANDIDATE_SCORING,
            PipelinePhase.COMPLETE: None,
            PipelinePhase.FAILED: None,
        }
        return mapping.get(phase)

    def run_pipeline_with_incident(
        self,
        scope: list[str] | None = None,
        dry_run: bool = False,
    ) -> dict:
        """Run the full v2 pipeline wrapped with incident tracking and escalation.

        Returns a dict with keys:
          - phases:     list[PhaseResult] from the underlying pipeline
          - incidents:  list[Incident] tracked during this run
          - escalated:  list[str] — incident IDs that were escalated to human
          - queued:     int — 1 if pipeline was queued due to rate limit, else 0
        """
        if not self.can_dispatch():
            logger.warning("Dispatch rate exceeded — pipeline queued")
            return {
                "phases": [],
                "incidents": [],
                "escalated": [],
                "queued": 1,
                "reason": "dispatch_rate_exceeded",
            }

        phases = self.governor.run_full_pipeline_v2(scope=scope, dry_run=dry_run)

        incidents: list[Incident] = []
        escalated: list[str] = []

        for phase_result in phases:
            incident_state = self._map_phase_to_incident_state(phase_result.phase)
            if incident_state is None:
                continue

            for agent_result in phase_result.results:
                for finding in getattr(agent_result, "findings", []):
                    try:
                        finding_dict = finding.to_dict()
                    except Exception as e:
                        logger.warning(f"Failed to convert finding to dict: {e}")
                        continue

                    confidence = finding_dict.get("confidence", 0.0)
                    if confidence < self._conf_threshold:
                        continue

                    control_id = finding_dict.get("control_id")
                    symbol_id = finding_dict.get("symbol_id") or finding_dict.get("affected_node", {}).get("symbol")
                    technique_id = finding_dict.get("technique_id")

                    existing: Incident | None = None
                    for inc in self._incidents.values():
                        if inc.control_id == control_id and inc.symbol_id == symbol_id and not inc.state.is_terminal:
                            existing = inc
                            break

                    if existing:
                        incident = existing
                        self.transition_incident(
                            incident.id,
                            incident_state,
                            rule_id="pipeline-phase-auto",
                            metadata={"phase": phase_result.phase.value},
                        )
                    else:
                        incident = self.create_incident(
                            finding_dict=finding_dict,
                            control_id=control_id,
                            symbol_id=symbol_id,
                            technique_id=technique_id,
                            confidence=confidence,
                        )
                        if incident_state != IncidentState.DETECTED:
                            self.transition_incident(
                                incident.id,
                                incident_state,
                                rule_id="dispatch-rule-auto",
                                metadata={"phase": phase_result.phase.value},
                            )

                    incidents.append(incident)
                    self.record_dispatch(incident.id)

                    escalation_reason = self.check_escalation(incident)
                    if escalation_reason:
                        self.transition_incident(
                            incident.id,
                            IncidentState.ESCALATED_TO_HUMAN,
                            rule_id=escalation_reason,
                            metadata={"escalation_reason": escalation_reason},
                        )
                        escalated.append(incident.id)

        for incident in self._incidents.values():
            if incident.state.is_terminal:
                continue
            escalation_reason = self.check_escalation(incident)
            if escalation_reason and incident.id not in escalated:
                self.transition_incident(
                    incident.id,
                    IncidentState.ESCALATED_TO_HUMAN,
                    rule_id=escalation_reason,
                    metadata={"escalation_reason": escalation_reason, "phase": "final"},
                )
                escalated.append(incident.id)

        if phases and phases[-1].status == AgentStatus.DONE and phases[-1].phase in (PipelinePhase.COMPLETE, PipelinePhase.SCORE_SELECT):
            for incident in self._incidents.values():
                if not incident.state.is_terminal and incident.id not in escalated:
                    self.transition_incident(
                        incident.id,
                        IncidentState.VERIFIED_RESOLVED,
                        rule_id="pipeline-complete",
                        metadata={"phase": "complete"},
                    )

        return {
            "phases": phases,
            "incidents": list(self._incidents.values()),
            "escalated": escalated,
            "queued": 0,
        }

    # ── Config accessors (spec §4 — all thresholds are configurable) ──────

    @property
    def auto_apply_threshold(self) -> float:
        return self._auto_apply_threshold

    @auto_apply_threshold.setter
    def auto_apply_threshold(self, value: float) -> None:
        self._auto_apply_threshold = value

    @property
    def max_fix_retries(self) -> int:
        return self._max_fix_retries

    @max_fix_retries.setter
    def max_fix_retries(self, value: int) -> None:
        self._max_fix_retries = value

    @property
    def max_dispatches_per_window(self) -> int:
        return self._max_dispatches_per_window

    @max_dispatches_per_window.setter
    def max_dispatches_per_window(self, value: int) -> None:
        self._max_dispatches_per_window = value

    @property
    def confidence_threshold(self) -> float:
        return self._conf_threshold

    @confidence_threshold.setter
    def confidence_threshold(self, value: float) -> None:
        self._conf_threshold = value

    # ── Status / passthrough ──────────────────────────────────────────────

    @property
    def config(self) -> dict:
        return self.governor.config

    def status(self) -> dict:
        base = self.governor.status()
        base["incident_count"] = len(self._incidents)
        base["incidents_by_state"] = {
            s.value: sum(1 for i in self._incidents.values() if i.state == s)
            for s in IncidentState
        }
        base["rules_loaded"] = len(self._rules)
        base["dispatches_in_window"] = len(self._dispatch_timestamps)
        return base

    def reset(self) -> None:
        """Reset pipeline and incident state."""
        self.governor.reset_pipeline()
        self._incidents.clear()
        self._dispatch_timestamps.clear()
        logger.info("GovernorEngine reset")
