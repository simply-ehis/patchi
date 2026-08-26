"""
Risk Gate for Patchi.

Every patch passes through the risk gate before anything touches disk.
The gate decides: auto-apply | ask user | block

Three modes (from config):
  CONFIRM     — every patch requires explicit user approval (Y/N)
  AUTO        — patches with risk_score ≤ threshold auto-apply; riskier ones ask
  AUTOPILOT   — all patches auto-apply; gate only blocks if contract is broken

Risk threshold for AUTO mode: config["risk_threshold"] (default 30).

Additional hard blocks (fire regardless of mode):
  1. App contract not locked — no fix runs until user confirms the contract
  2. No-touch restriction violated — patch targets a restricted path
  3. Blast radius report required — config["require_blast_radius_on_high_risk"] = True
     and risk_score ≥ 61 — blast radius must be computed and shown before applying

Gate decisions:
  ALLOW_AUTO   — apply without asking (low risk + AUTO/AUTOPILOT mode)
  REQUIRE_REVIEW — surface to user for approval (confirm mode OR high risk)
  BLOCK        — refuse entirely (contract not locked, restricted path)

The gate NEVER raises exceptions. It always returns a GateDecision.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from patchi.core import config as cfg
from patchi.core import memory as mem
from patchi.core.constants import Mode, RiskLevel
from patchi.core.fix.patch import Patch

_log = logging.getLogger("patchi.fix.risk_gate")

# ── Gate decision ──────────────────────────────────────────────────────────────


class GateDecision(StrEnum):
    ALLOW_AUTO = "allow_auto"  # apply immediately
    REQUIRE_REVIEW = "require_review"  # surface to user
    BLOCK = "block"  # hard stop


@dataclass
class GateResult:
    decision: GateDecision
    reason: str
    patch_id: str
    risk_score: int
    risk_level: str
    confidence: int
    blast_radius: int
    blocks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requires_blast_report: bool = False

    @property
    def is_blocked(self) -> bool:
        return self.decision == GateDecision.BLOCK

    @property
    def is_auto(self) -> bool:
        return self.decision == GateDecision.ALLOW_AUTO

    @property
    def needs_review(self) -> bool:
        return self.decision == GateDecision.REQUIRE_REVIEW

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "patch_id": self.patch_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "blast_radius": self.blast_radius,
            "blocks": self.blocks,
            "warnings": self.warnings,
            "requires_blast_report": self.requires_blast_report,
        }


# ── Risk gate ──────────────────────────────────────────────────────────────────


class RiskGate:
    """
    Evaluates every patch before it is applied.

    Usage:
        gate = RiskGate(project_root)
        result = gate.evaluate(patch)
        if result.is_blocked:
            # tell user why
        elif result.is_auto:
            # apply now
        else:
            # surface for review
    """

    def __init__(self, root: Path):
        self.root = root
        try:
            self._config = cfg.load(root)
        except Exception as e:
            _log.warning(
                "Failed to load config for %s — falling back to defaults (restricted-path "
                "protections may be affected): %s",
                root,
                e,
            )
            self._config = {}
        try:
            self._brain = mem.get_brain(root)
        except Exception as e:
            _log.warning("Failed to load brain data for %s — falling back to empty: %s", root, e)
            self._brain = {}

    def evaluate(self, patch: Patch) -> GateResult:
        """Run all gate checks and return a decision."""
        blocks: list[str] = []
        warnings: list[str] = []

        mode = self._get_mode()
        risk_threshold = self._config.get("risk_threshold", 30)
        risk_level = RiskLevel.from_score(patch.risk_score).value
        requires_blast = False

        # ── Hard blocks ────────────────────────────────────────────────────────

        # 1. Contract must be locked before any fix runs
        if not self._brain.get("contract_locked"):
            blocks.append(
                "App contract not confirmed. Run 'p scan' and confirm your critical flows first. "
                "No fixes will apply until the contract is locked."
            )

        # 2. Restricted path check
        restricted = self._restricted_paths()
        for change in patch.changes:
            for path, rtype in restricted:
                if change.path.startswith(path.rstrip("/")):
                    if rtype == "sensitive":
                        warnings.append(
                            f"'{change.path}' is in a sensitive zone ({path}). "
                            "Proceed with caution."
                        )
                    else:
                        blocks.append(
                            f"'{change.path}' is in a restricted {rtype} zone ({path}). "
                            "Modify restrictions with 'p restrict'."
                        )

        # 3. Charter boundary check — agent fixes must not violate guard rails
        try:
            from patchi.core.security.charter import (
                RuleType,
                check_boundary_violations,
                load_charter,
            )

            charter = load_charter(self.root)
            if charter.rules:
                # Build import edges from proposed changes
                import_edges: list[tuple[str, str]] = []
                for change in patch.changes:
                    if change.proposed:
                        # Extract import statements from proposed code
                        import re as _re
                        for m in _re.finditer(
                            r'from\s+(\S+)\s+import\s+\w+', change.proposed
                        ):
                            import_edges.append((change.path, m.group(1)))
                        for m in _re.finditer(
                            r'import\s+(\S+)', change.proposed
                        ):
                            import_edges.append((change.path, m.group(1)))

                # Check boundary rules
                boundary_violations = check_boundary_violations(charter, import_edges)
                for v in boundary_violations:
                    blocks.append(
                        f"Charter violation [{v.rule_id}]: {v.message}. "
                        f"{v.suggestion}"
                    )

                # Check convention rules (file size limits)
                for rule in charter.rules:
                    if rule.type == RuleType.CONVENTION and rule.enabled:
                        if rule.max_value > 0 and rule.metric == "lines":
                            max_lines = rule.max_value
                        if max_lines and max_lines > 0:
                            for change in patch.changes:
                                if change.path.endswith((".py", ".ts", ".js")):
                                    new_lines = (
                                        (change.proposed or "").count("\n") + 1
                                    )
                                    if new_lines > max_lines:
                                        blocks.append(
                                            f"Charter violation [{rule.id}]: "
                                            f"{change.path} would be {new_lines} lines "
                                            f"(max {max_lines}). {rule.description}"
                                        )
        except Exception as e:
            _log.debug("Charter check skipped: %s", e)

        # 4. Blast radius report required for high-risk patches
        if (
            self._config.get("require_blast_radius_on_high_risk", True)
            and patch.risk_score >= 61
            and patch.blast_radius == 0
        ):
            blocks.append(
                f"High-risk patch (score {patch.risk_score}) requires a blast radius report. "
                "Patchi is computing it — this patch will be re-evaluated once ready."
            )
            requires_blast = True

        # ── Warnings ───────────────────────────────────────────────────────────

        if patch.confidence < 70:
            warnings.append(
                f"Low confidence ({patch.confidence}%). "
                "Patchi is less certain than usual about this fix."
            )

        if patch.blast_radius > 10:
            warnings.append(
                f"High blast radius: {patch.blast_radius} files depend on the changed file(s). "
                "Thorough testing is recommended."
            )

        if patch.total_lines_changed > 100:
            warnings.append(
                f"Large patch: {patch.total_lines_changed} lines changed across "
                f"{patch.file_count} file(s)."
            )

        # Secrets gate: check if proposed code introduces new secrets
        try:
            from patchi.core.security.secrets_guard import gate_check_proposed_code

            for change in patch.changes:
                if change.proposed:
                    safe, secret_findings = gate_check_proposed_code(change.proposed, change.path)
                    if not safe:
                        blocks.append(
                            f"Secrets guard: proposed change to '{change.path}' introduces "
                            f"{len(secret_findings)} secret(s). Fix blocked."
                        )
        except ImportError:
            pass

        # ── Determine decision ─────────────────────────────────────────────────

        if blocks:
            return GateResult(
                decision=GateDecision.BLOCK,
                reason=blocks[0],
                patch_id=patch.id,
                risk_score=patch.risk_score,
                risk_level=risk_level,
                confidence=patch.confidence,
                blast_radius=patch.blast_radius,
                blocks=blocks,
                warnings=warnings,
                requires_blast_report=requires_blast,
            )

        # Test-weakening guard: a patch that only edits test files (set by the
        # verify loop / fix command) must NEVER auto-apply — it goes to the
        # human review queue regardless of mode, even AUTOPILOT.
        if patch.requires_review:
            return GateResult(
                decision=GateDecision.REQUIRE_REVIEW,
                reason=(
                    "Patch only changes test file(s) — flagged for human review "
                    "(test-weakening edits are never auto-applied)."
                ),
                patch_id=patch.id,
                risk_score=patch.risk_score,
                risk_level=risk_level,
                confidence=patch.confidence,
                blast_radius=patch.blast_radius,
                blocks=[],
                warnings=warnings + ["Test-weakening patch: only test files changed."],
                requires_blast_report=requires_blast,
            )

        # Mode-based routing
        if mode == Mode.CONFIRM:
            # Always ask in CONFIRM mode
            decision = GateDecision.REQUIRE_REVIEW
            reason = "CONFIRM mode — every fix requires approval."

        elif mode == Mode.AUTO:
            if patch.risk_score <= risk_threshold:
                decision = GateDecision.ALLOW_AUTO
                reason = f"AUTO mode — risk score {patch.risk_score} ≤ threshold {risk_threshold}."
            else:
                decision = GateDecision.REQUIRE_REVIEW
                reason = (
                    f"AUTO mode — risk score {patch.risk_score} exceeds threshold {risk_threshold}. "
                    "Surfaced for review."
                )

        else:  # AUTOPILOT
            decision = GateDecision.ALLOW_AUTO
            reason = "AUTOPILOT mode — all fixes apply automatically."
            if patch.risk_score >= 61:
                warnings.append(
                    f"High-risk fix applied automatically (AUTOPILOT). "
                    f"Risk score: {patch.risk_score}. Switch to AUTO mode for manual review."
                )

        # ── Quiet hours check ─────────────────────────────────────────────────
        # In quiet hours, auto-apply is blocked even in AUTO/AUTOPILOT modes
        if decision == GateDecision.ALLOW_AUTO and self._is_quiet_hours():
            decision = GateDecision.REQUIRE_REVIEW
            reason = f"Quiet hours active — auto-apply deferred to {self._config.get('quiet_hours_end', 'end')}."
            warnings.append("Quiet hours: auto-apply blocked. Patch queued for review.")

        return GateResult(
            decision=GateDecision(decision),
            reason=reason,
            patch_id=patch.id,
            risk_score=patch.risk_score,
            risk_level=risk_level,
            confidence=patch.confidence,
            blast_radius=patch.blast_radius,
            blocks=blocks,
            warnings=warnings,
            requires_blast_report=requires_blast,
        )

    def _is_quiet_hours(self) -> bool:
        """Check if current local time falls within configured quiet hours."""
        quiet_hours = self._config.get("quiet_hours", {})
        if not quiet_hours.get("enabled", False):
            return False
        start = quiet_hours.get("start", "")
        end = quiet_hours.get("end", "")
        if not start or not end:
            return False
        try:
            now = datetime.datetime.now()
            now_minutes = now.hour * 60 + now.minute
            start_parts = start.split(":")
            end_parts = end.split(":")
            start_minutes = int(start_parts[0]) * 60 + int(start_parts[1])
            end_minutes = int(end_parts[0]) * 60 + int(end_parts[1])
            if start_minutes <= end_minutes:
                return start_minutes <= now_minutes < end_minutes
            return now_minutes >= start_minutes or now_minutes < end_minutes
        except (ValueError, IndexError, AttributeError):
            return False

    def _get_mode(self) -> Mode:
        try:
            return cfg.get_mode(self.root)
        except Exception as e:
            _log.warning(
                "Failed to read mode from config — defaulting to CONFIRM (safest option): %s", e
            )
            return Mode.CONFIRM

    def _restricted_paths(self) -> list[tuple[str, str]]:
        restrictions = self._config.get("restrictions", [])
        return [
            (r["path"], r.get("type", "no_touch"))
            for r in restrictions
            if r.get("enabled", True) and r.get("type") in ("no_touch", "scan_only", "sensitive")
        ]
