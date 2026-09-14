"""
Defense Layer — takes high-confidence findings and produces concrete defense actions.

Delegates execution to adapters in ``patchi.core.security.defenders``.
Each finding maps to a defense action type:
  fix_code, update_dependency, block_ip, rotate_secret, patch_config,
  crypto_fix, auth_middleware, invalidate_session, enforce_rate_limit,
  suspend_account, block_ws_origin, escalate (fallback).

All code changes pass through the existing RiskGate which enforces
CONFIRM/AUTO/AUTOPILOT modes, no-touch paths, quiet hours, blast radius.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from patchi.core.fix.risk_gate import RiskGate
from patchi.core.security.defenders import (
    DefendResult,
    DefenseAction,
    get_adapter,
)
from patchi.core.security.history import _get_db

_log = logging.getLogger("patchi.security.defense_layer")

# Re-export for backward compat
__all__ = ["DefenseAction", "DefendResult", "DefenseLayer"]

# ── Finding → Action type mapping ────────────────────────────────────────────

_FINDING_TYPE_TO_ACTION: dict[str, str] = {
    # ── Injection ───────────────────────────────────────────────────────
    "sqli": "fix_code",
    "xss": "fix_code",
    "command_injection": "fix_code",
    "path_traversal": "fix_code",
    "ssrf": "fix_code",
    "ssti": "fix_code",
    "injection": "fix_code",
    # ── Secrets ─────────────────────────────────────────────────────────
    "hardcoded_secret": "rotate_secret",
    "api_key": "rotate_secret",
    "password_in_code": "rotate_secret",
    # ── Dependency ──────────────────────────────────────────────────────
    "cve": "update_dependency",
    "vulnerable_dependency": "update_dependency",
    "unpinned_dependency": "update_dependency",
    # ── Config ──────────────────────────────────────────────────────────
    "debug_mode": "patch_config",
    "missing_header": "patch_config",
    "cors_wildcard": "patch_config",
    "weak_tls": "patch_config",
    "misconfiguration": "patch_config",
    # ── Block IP ────────────────────────────────────────────────────────
    "brute_force": "block_ip",
    "scanner_sweep": "block_ip",
    "injection_probe": "block_ip",
    "rate_spike": "block_ip",
    # ── LLM Security Agent ──────────────────────────────────────────────
    "prompt_injection": "fix_code",
    "insecure_llm_output": "fix_code",
    "insecure_llm_output_rendering": "fix_code",
    "recursive_agent_loop": "fix_code",
    "untrusted_model_source": "fix_code",
    "sensitive_data_in_prompt": "fix_code",
    "excessive_tool_permissions": "fix_code",
    "tool_shell_injection": "fix_code",
    # ── Business Logic Agent ────────────────────────────────────────────
    "mass_assignment": "fix_code",
    "excessive_data_exposure": "fix_code",
    "missing_pagination": "patch_config",
    "idor_missing_ownership_check": "fix_code",
    "unvalidated_state_transition": "fix_code",
    # ── Weak crypto ─────────────────────────────────────────────────────
    "weak_cipher": "crypto_fix",
    "weak_hash": "crypto_fix",
    "custom_crypto": "crypto_fix",
    "insufficient_key_size": "crypto_fix",
    # ── Auth ────────────────────────────────────────────────────────────
    "missing_auth": "auth_middleware",
    "missing_authorization": "fix_code",
    "weak_password_policy": "patch_config",
    "missing_csrf": "fix_code",
    "jwt_weakness": "fix_code",
    "open_redirect": "fix_code",
    # ── Session management ──────────────────────────────────────────────
    "session_fixation": "invalidate_session",
    "user_controlled_session_id": "invalidate_session",
    "missing_session_timeout": "patch_config",
    "missing_session_invalidation": "fix_code",
    "insecure_session_storage": "fix_code",
    "missing_httponly": "patch_config",
    "missing_secure_flag": "patch_config",
    "session_in_url": "fix_code",
    # ── Rate limiting ───────────────────────────────────────────────────
    "missing_rate_limit": "enforce_rate_limit",
    # ── Excessive agency ────────────────────────────────────────────────
    "excessive_agency": "suspend_account",
    # ── WebSocket ───────────────────────────────────────────────────────
    "missing_origin_validation": "block_ws_origin",
    "unencrypted_websocket": "fix_code",
    "websocket_no_input_validation": "fix_code",
    "websocket_no_auth": "fix_code",
    "websocket_no_limit": "patch_config",
    "sensitive_data_in_websocket": "fix_code",
    # ── Container / IaC ─────────────────────────────────────────────────
    "container_privileged": "fix_code",
    "container_root_user": "fix_code",
    "unpinned_base_image": "fix_code",
    "k8s_privileged": "fix_code",
    "k8s_host_network": "fix_code",
    "s3_public_access": "fix_code",
    "security_group_wide_open": "fix_code",
    # ── Supply chain ────────────────────────────────────────────────────
    "typosquatting": "update_dependency",
    "deprecated_package": "update_dependency",
    "license_violation": "escalate",
}


# ── Defense Layer ────────────────────────────────────────────────────────────


class DefenseLayer:
    """Executes defense actions for high-confidence findings."""

    def __init__(self, root: Path, config: dict | None = None):
        self.root = root
        self.config = config or {}
        self.risk_gate = RiskGate(root)

    @classmethod
    def _finding_to_action_map(cls) -> dict[str, str]:
        """Return the finding-type → action-type mapping."""
        return _FINDING_TYPE_TO_ACTION.copy()

    def defend_all(self, findings: list) -> list[DefendResult]:
        """Defend against all high-confidence findings. Returns results list."""
        results: list[DefendResult] = []
        for gf in findings:
            action = self._finding_to_action(gf)
            result = self._execute(action)
            results.append(result)
            self._log_defense_result(result)
        return results

    def _finding_to_action(self, gf) -> DefenseAction:
        """Map a gated finding to the appropriate defense action type."""
        f = gf.finding
        ftype = f.type.lower()

        # Check exact match first, then partial match
        action_type = _FINDING_TYPE_TO_ACTION.get(ftype)
        if action_type is None:
            for key, val in _FINDING_TYPE_TO_ACTION.items():
                if key in ftype:
                    action_type = val
                    break
        if action_type is None:
            action_type = "escalate"

        target = f.file
        if action_type == "block_ip":
            target = f.extra.get("ip", "") if hasattr(f, "extra") and isinstance(f.extra, dict) else ""

        return DefenseAction(
            type=action_type,
            target=target,
            finding=f,
            severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            fix_code=f.suggestion or "",
        )

    def _execute(self, action: DefenseAction) -> DefendResult:
        """Execute a defense action via the adapter registry."""
        adapter = get_adapter(action.type, root=self.root, risk_gate=self.risk_gate)
        return adapter.execute(action)

    def _log_defense_result(self, result: DefendResult) -> None:
        """Log defense action result to SQLite history."""
        try:
            conn = _get_db(self.root)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS defense_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT,
                    target TEXT,
                    severity TEXT,
                    finding_type TEXT,
                    finding_file TEXT
                )"""
            )
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            conn.execute(
                "INSERT INTO defense_actions (timestamp, action, reason, target, severity, finding_type, finding_file)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    result.action,
                    result.reason[:500] if result.reason else "",
                    result.defense_action.target if result.defense_action else "",
                    result.defense_action.severity if result.defense_action else "",
                    result.defense_action.finding.type if result.defense_action else "",
                    result.defense_action.finding.file if result.defense_action else "",
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            _log.warning("DefenseLayer._log_defense_result failed: %s", e)
