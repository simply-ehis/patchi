"""Adapter: invalidate_session — queue session invalidation for compromised users."""

from __future__ import annotations

import json
import logging
import time

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.invalidate_session")


class InvalidateSessionAdapter(BaseAdapter):
    """Invalidate all active sessions for a user."""

    action_type = "invalidate_session"

    def execute(self, action: DefenseAction) -> DefendResult:
        inval_path = self.root / ".patchi" / "invalidate_sessions.json"
        target = action.target or "unknown_user"
        pending: dict = {}
        if inval_path.exists():
            try:
                pending = json.loads(inval_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("InvalidateSessionAdapter read failed: %s", e)
                pending = {}
        pending[target] = {
            "timestamp": time.time(),
            "reason": action.finding.message or "Session compromise detected",
            "finding_type": action.finding.type,
        }
        inval_path.parent.mkdir(parents=True, exist_ok=True)
        inval_path.write_text(json.dumps(pending, indent=2), encoding="utf-8")
        return DefendResult(
            action="applied",
            reason=f"Queued session invalidation for {target} — written to .patchi/invalidate_sessions.json",
            defense_action=action,
        )
