"""Adapter: block_ws_origin — block a WebSocket origin via config patch."""

from __future__ import annotations

import json
import logging

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.block_ws_origin")


class BlockWsOriginAdapter(BaseAdapter):
    """Block a WebSocket origin via config patch."""

    action_type = "block_ws_origin"

    def execute(self, action: DefenseAction) -> DefendResult:
        ws_path = self.root / ".patchi" / "blocked_ws_origins.json"
        target = action.target or "unknown_origin"
        blocked: list = []
        if ws_path.exists():
            try:
                blocked = json.loads(ws_path.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("BlockWsOriginAdapter read failed: %s", e)
                blocked = []
        if target not in blocked:
            blocked.append(target)
        ws_path.parent.mkdir(parents=True, exist_ok=True)
        ws_path.write_text(json.dumps(blocked, indent=2), encoding="utf-8")
        return DefendResult(
            action="applied",
            reason=f"Blocked WebSocket origin: {target} — written to .patchi/blocked_ws_origins.json",
            defense_action=action,
        )
