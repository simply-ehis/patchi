"""
Governance & Audit (Layer 3) — action logging and policy gates.

- patchi_action_log: SQLite audit trail of all Patchi actions
- patchi_policy_gate: YAML allow/deny policy check before destructive actions
"""

from __future__ import annotations
import logging

import sqlite3
import time
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)

# ── SQLite Action Log ─────────────────────────────────────────────────────────

_DB_NAME = "patchi_actions.db"

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS action_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    agent TEXT,
    detail TEXT,
    status TEXT DEFAULT 'ok'
);
"""


_log = logging.getLogger("patchi.security.governance")


def _get_db(root: Path) -> sqlite3.Connection:
    db_path = root / ".patchi" / _DB_NAME
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10.0)
    # WAL + busy_timeout make concurrent writers (parallel agents calling
    # patchi_action_log) queue instead of failing with "database or disk is full".
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute(_CREATE_TABLES)
    return conn


def patchi_action_log(
    root: Path, action: str, target: str, agent: str = "", detail: str = "", status: str = "ok"
) -> None:
    """Log an action to the local SQLite audit trail."""
    row = (
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        action,
        target,
        agent,
        detail,
        status,
    )
    last_err: Exception | None = None
    for attempt in range(3):
        try:
            conn = _get_db(root)
            try:
                conn.execute(
                    "INSERT INTO action_log (timestamp, action, target, agent, detail, status) VALUES (?, ?, ?, ?, ?, ?)",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
            return
        except sqlite3.DatabaseError as e:  # OperationalError is a subclass
            last_err = e
            time.sleep(0.1 * (attempt + 1))
    _log.warning("patchi_action_log failed after 3 attempts: %s", last_err)


def patchi_get_actions(root: Path, limit: int = 50) -> list[dict]:
    """Retrieve recent actions from the audit log."""
    conn = _get_db(root)
    try:
        cursor = conn.execute(
            "SELECT timestamp, action, target, agent, detail, status FROM action_log ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "timestamp": r[0],
                "action": r[1],
                "target": r[2],
                "agent": r[3],
                "detail": r[4],
                "status": r[5],
            }
            for r in cursor.fetchall()
        ]
    finally:
        conn.close()


# ── Policy Gate ───────────────────────────────────────────────────────────────

_DEFAULT_POLICY = {
    "never_touch": [".env", "docker-compose.yml", "*.key", "*.pem", "*.p12"],
    "auto_apply_max_severity": "medium",
    "require_confirmation_above": "high",
}


def _load_policy(root: Path) -> dict:
    """Load policy from .patchi/policies/default.yaml or use defaults."""
    policy_file = root / ".patchi" / "policies" / "default.yaml"
    if policy_file.exists():
        try:
            import yaml

            data = yaml.safe_load(policy_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {**_DEFAULT_POLICY, **data}
        except Exception as e:
            _log.warning("_load_policy failed: %s", e)
    return _DEFAULT_POLICY.copy()


def patchi_policy_gate(
    root: Path, action: str, target: str, severity: str = "medium"
) -> tuple[bool, str]:
    """
    Check if an action is allowed by the policy gate.
    Returns (allowed, reason).
    """
    policy = _load_policy(root)

    # Check never_touch patterns
    from fnmatch import fnmatch

    for pattern in policy.get("never_touch", []):
        if fnmatch(target, pattern) or fnmatch(target.split("/")[-1], pattern):
            return (
                False,
                f"Policy blocks action on '{target}' (matches never_touch pattern: {pattern})",
            )

    # Check severity threshold
    max_auto = policy.get("auto_apply_max_severity", "medium")
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if sev_order.get(severity, 0) > sev_order.get(max_auto, 2):
        return (
            False,
            f"Severity '{severity}' exceeds auto-apply threshold '{max_auto}' — requires confirmation",
        )

    return True, "Allowed by policy"


# ── Governance Agent ──────────────────────────────────────────────────────────


@register
class GovernanceAgent(BaseAgent):
    """Action logging and policy gate enforcement."""

    name = "GovernanceAgent"
    group = AgentGroup.GUARD
    timeout = 30

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Log that a governance check was performed
        patchi_action_log(inp.root, "governance_check", "security_scan", agent=self.name)

        # Check policy violations — use pattern-targeted glob instead of O(all files) walk (ARCH-06 fix)
        policy = _load_policy(inp.root)

        never_touch_patterns = policy.get("never_touch", [])
        if not never_touch_patterns:
            result.files_scanned = 0
            return

        # Only walk files that could match the patterns — much faster than safe_rglob("*")
        scanned = 0
        for pattern in never_touch_patterns:
            # Use glob directly with the pattern to avoid full tree walk
            for fpath in inp.root.rglob(pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                scanned += 1
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="policy_violation",
                        severity=Severity.HIGH,
                        file=rel,
                        message=f"File matches never_touch policy pattern: {pattern}",
                    )
                )

        result.files_scanned = scanned
