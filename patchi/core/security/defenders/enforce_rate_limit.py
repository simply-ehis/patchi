"""Adapter: enforce_rate_limit — add rate limiting middleware."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from patchi.core.fix.patch import FileChange, Patch

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.enforce_rate_limit")


class EnforceRateLimitAdapter(BaseAdapter):
    """Enforce rate limiting on an endpoint by adding middleware."""

    action_type = "enforce_rate_limit"

    def execute(self, action: DefenseAction) -> DefendResult:
        if not action.target or not Path(action.target).exists():
            return DefendResult(
                action="skipped",
                reason=f"File does not exist: {action.target}",
                defense_action=action,
            )
        fpath = Path(action.target)
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            return DefendResult(action="blocked", reason=f"Read error: {e}", defense_action=action)

        changes = []
        if "flask" in content.lower():
            if "from flask_limiter import Limiter" not in content:
                changes.append(
                    FileChange(
                        path=str(fpath),
                        original=content,
                        proposed=(
                            "from flask_limiter import Limiter\n"
                            "from flask_limiter.util import get_remote_address\n\n"
                            "limiter = Limiter(key_func=get_remote_address)\n" + content
                        ),
                    )
                )
        elif "fastapi" in content.lower():
            if (
                "from slowapi import Limiter" not in content
                and "from fastapi import Depends" in content
            ):
                changes.append(
                    FileChange(
                        path=str(fpath),
                        original=content,
                        proposed=(
                            "from slowapi import Limiter, _rate_limit_exceeded_handler\n"
                            "from slowapi.util import get_remote_address\n" + content
                        ),
                    )
                )

        if not changes:
            return DefendResult(
                action="queued",
                reason="Add rate limit middleware manually — no framework template matched",
                defense_action=action,
            )

        patch = Patch(
            id=uuid.uuid4().hex[:12],
            agent=action.finding.agent,
            finding_id=action.finding.type,
            patch_type="CONFIG",
            changes=changes,
            description="Add rate limiting middleware",
            risk_score=15,
            confidence=65,
            blast_radius=1,
        )
        gate_result = self.risk_gate.evaluate(patch)
        if gate_result.is_auto:
            try:
                patch.apply()
                return DefendResult(
                    action="applied",
                    reason="Rate limit middleware template added",
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
        else:
            return DefendResult(
                action="queued" if not gate_result.is_blocked else "blocked",
                reason=gate_result.reason,
                defense_action=action,
                patch=patch,
                gate_result=gate_result,
            )
