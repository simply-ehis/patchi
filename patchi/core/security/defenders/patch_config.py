"""Adapter: patch_config — edit config file with known-good values."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from patchi.core.fix.patch import FileChange, Patch

from .base import BaseAdapter, DefendResult, DefenseAction
from .fix_code import ACTION_LABELS

_log = logging.getLogger("patchi.security.defenders.patch_config")


class PatchConfigAdapter(BaseAdapter):
    """Patch a configuration file with known-good values."""

    action_type = "patch_config"

    def execute(self, action: DefenseAction) -> DefendResult:
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"Config file does not exist: {action.target}",
                defense_action=action,
            )

        change = FileChange(path=action.target, original="", proposed=action.fix_code)
        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="CONFIG",
            changes=[change],
            description=ACTION_LABELS.get(action.type, "Config patch"),
            risk_score=self._estimate_risk(action),
            confidence=85,
            blast_radius=0,
        )

        gate_result = self.risk_gate.evaluate(patch)

        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason=f"Config auto-patched: {gate_result.reason}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
            except Exception as e:
                return DefendResult(
                    action="blocked",
                    reason=f"Config patch failed: {e}",
                    defense_action=action,
                    patch=patch,
                    gate_result=gate_result,
                )
        else:
            return DefendResult(
                action="queued" if not gate_result.is_blocked else "blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
