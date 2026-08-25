"""Adapter: suspend_account — suspend a compromised account (hosted mode only)."""

from __future__ import annotations

import json
import logging
import time

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.suspend_account")


class SuspendAccountAdapter(BaseAdapter):
    """Suspend a compromised account (hosted mode only)."""

    action_type = "suspend_account"

    def execute(self, action: DefenseAction) -> DefendResult:
        susp_path = self.root / ".patchi" / "suspend_accounts.json"
        target = action.target or "unknown_account"
        pending: dict = {}
        if susp_path.exists():
            try:
                pending = json.loads(susp_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("SuspendAccountAdapter read failed: %s", e)
                pending = {}
        pending[target] = {
            "timestamp": time.time(),
            "reason": action.finding.message or "Account compromise detected",
            "finding_type": action.finding.type,
            "severity": action.severity,
        }
        susp_path.parent.mkdir(parents=True, exist_ok=True)
        susp_path.write_text(json.dumps(pending, indent=2), encoding="utf-8")
        return DefendResult(
            action="applied",
            reason=f"Queued account suspension for {target} — written to .patchi/suspend_accounts.json",
            defense_action=action,
        )
