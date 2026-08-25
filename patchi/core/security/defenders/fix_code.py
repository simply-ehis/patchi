"""Adapter: fix_code — create Patch, pass through RiskGate, apply if allowed."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from patchi.core.fix.patch import FileChange, Patch

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.fix_code")

# Human-readable labels for each action type (shared across adapters)
ACTION_LABELS: dict[str, str] = {
    "fix_code": "Fix code vulnerability",
    "update_dependency": "Update vulnerable dependency",
    "block_ip": "Block malicious IP",
    "rotate_secret": "Rotate exposed secret",
    "patch_config": "Patch security configuration",
    "crypto_fix": "Replace weak crypto with modern algorithms",
    "auth_middleware": "Add authentication middleware",
    "invalidate_session": "Invalidate active sessions",
    "enforce_rate_limit": "Enforce rate limiting middleware",
    "suspend_account": "Suspend compromised account",
    "block_ws_origin": "Block WebSocket origin",
    "escalate": "Escalate for human review",
}


class FixCodeAdapter(BaseAdapter):
    """Create a Patch and pass through RiskGate for mode-based decision."""

    action_type = "fix_code"

    def execute(self, action: DefenseAction) -> DefendResult:
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"File does not exist: {action.target}",
                defense_action=action,
            )

        change = FileChange(path=action.target, original="", proposed=action.fix_code)
        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="SECURITY",
            changes=[change],
            description=ACTION_LABELS.get(action.type, "Security fix"),
            risk_score=self._estimate_risk(action),
            confidence=90,
            blast_radius=0,
        )

        gate_result = self.risk_gate.evaluate(patch)

        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason=f"Auto-applied: {gate_result.reason}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Apply failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        elif gate_result.is_blocked:
            return DefendResult(
                action="blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
        else:
            return DefendResult(
                action="queued",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
