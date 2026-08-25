"""Base adapter for defense actions.

Each concrete adapter handles one defense action type
(fix_code, block_ip, rotate_secret, etc.) and implements
``execute(action) -> DefendResult``.
"""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from pathlib import Path

from patchi.core.agents.base import Finding
from patchi.core.fix.patch import Patch
from patchi.core.fix.risk_gate import GateResult

_log_name = "patchi.security.defenders"


@dataclass
class DefenseAction:
    """A concrete action to defend against a confirmed finding."""

    type: str
    target: str
    finding: Finding
    severity: str
    fix_code: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "target": self.target,
            "severity": self.severity,
            "finding_id": self.finding.type,
            "finding_file": self.finding.file,
        }


@dataclass
class DefendResult:
    """Result of executing a defense action."""

    action: str  # "applied" | "queued" | "blocked" | "skipped"
    reason: str
    defense_action: DefenseAction | None = None
    patch: Patch | None = None
    gate_result: GateResult | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = {
            "action": self.action,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }
        if self.defense_action:
            d["defense_action"] = self.defense_action.to_dict()
        if self.patch:
            d["patch_id"] = self.patch.id
        return d


class BaseAdapter(abc.ABC):
    """All defense adapters must subclass this."""

    action_type: str  # must be set by subclass

    def __init__(self, root: Path, risk_gate):
        self.root = root
        self.risk_gate = risk_gate

    @abc.abstractmethod
    def execute(self, action: DefenseAction) -> DefendResult:
        """Execute the defense action and return a result."""

    def _estimate_risk(self, action: DefenseAction) -> int:
        """Estimate risk score for a defense action (0-100)."""
        sev_scores = {"critical": 80, "high": 60, "medium": 40, "low": 20, "info": 10}
        base = sev_scores.get(action.severity, 30)
        action_risk = {
            "fix_code": 0,
            "update_dependency": 10,
            "block_ip": 5,
            "rotate_secret": 15,
            "patch_config": 20,
            "crypto_fix": 5,
            "auth_middleware": 15,
            "invalidate_session": 25,
            "enforce_rate_limit": 10,
            "suspend_account": 40,
            "block_ws_origin": 10,
            "escalate": 0,
        }
        return min(100, base + action_risk.get(action.type, 0))
