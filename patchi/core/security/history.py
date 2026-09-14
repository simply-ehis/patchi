"""
Security History & Analytics (Layer 4) — scan history and findings lifecycle tracking.

SQLite-backed storage for:
- Scan history (every security scan recorded)
- Findings lifecycle (open → fixed → verified → false_positive)
- Trend analytics (findings over time, mean time-to-fix)
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
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

_DB_NAME = "patchi_history.db"

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS scan_history (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    repo_path TEXT,
    tool TEXT,
    findings_count INTEGER DEFAULT 0,
    severity_breakdown TEXT,
    duration_ms INTEGER DEFAULT 0,
    health_score INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT,
    rule_id TEXT,
    file TEXT,
    line INTEGER DEFAULT 0,
    severity TEXT,
    status TEXT DEFAULT 'open',
    first_seen TEXT,
    resolved_at TEXT,
    evidence_path TEXT
);
"""


def _get_db(root: Path) -> sqlite3.Connection:
    db_path = root / ".patchi" / _DB_NAME
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_CREATE_TABLES)
    # Migrate existing DBs that don't have newer columns
    for col_sql in [
        "ALTER TABLE scan_history ADD COLUMN health_score INTEGER DEFAULT 0",
        "ALTER TABLE scan_history ADD COLUMN metrics TEXT DEFAULT '{}'",
        "ALTER TABLE scan_history ADD COLUMN agent_group TEXT DEFAULT ''",
    ]:
        try:
            conn.execute(col_sql)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # Column already exists
    return conn


def patchi_record_scan(
    root: Path,
    tool: str,
    findings: list[dict],
    duration_ms: int = 0,
    health_score: int = 0,
    metrics: dict | None = None,
    agent_group: str = "",
) -> str:
    """Record a scan. Returns scan_id."""
    scan_id = uuid.uuid4().hex[:12]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        by_sev[sev] = by_sev.get(sev, 0) + 1

    conn = _get_db(root)
    try:
        conn.execute(
            "INSERT INTO scan_history (scan_id, timestamp, repo_path, tool, findings_count, severity_breakdown,"
            " duration_ms, health_score, metrics, agent_group) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                now,
                str(root),
                tool,
                len(findings),
                json.dumps(by_sev),
                duration_ms,
                health_score,
                json.dumps(metrics or {}),
                agent_group,
            ),
        )
        for f in findings:
            fid = uuid.uuid4().hex
            conn.execute(
                "INSERT OR REPLACE INTO findings (finding_id, scan_id, rule_id, file, line, severity, status,"
                " first_seen) VALUES (?, ?, ?, ?, ?, ?, 'open', ?)",
                (
                    fid,
                    scan_id,
                    f.get("type", ""),
                    f.get("file", ""),
                    f.get("line", 0),
                    f.get("severity", "info"),
                    now,
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return scan_id


def patchi_verify_finding(root: Path, finding_id: str) -> None:
    """Mark a finding as verified (fix confirmed)."""
    conn = _get_db(root)
    try:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn.execute(
            "UPDATE findings SET status = 'verified', resolved_at = ? WHERE finding_id = ?",
            (now, finding_id),
        )
        conn.commit()
    finally:
        conn.close()


def patchi_get_history(root: Path, limit: int = 20) -> list[dict]:
    """Get recent scan history."""
    conn = _get_db(root)
    try:
        cursor = conn.execute(
            "SELECT scan_id, timestamp, tool, findings_count, severity_breakdown, duration_ms, health_score FROM"
            " scan_history ORDER BY rowid DESC LIMIT ?",
            (limit,),
        )
        return [
            {
                "scan_id": r[0],
                "timestamp": r[1],
                "tool": r[2],
                "findings_count": r[3],
                "severity_breakdown": json.loads(r[4] or "{}"),
                "duration_ms": r[5],
                "health_score": r[6] or 0,
            }
            for r in cursor.fetchall()
        ]
    finally:
        conn.close()


def patchi_get_severity_trends(root: Path, days: int = 90) -> dict:
    """Severity breakdown per day — ready for trend charts.

    Returns::
        {"labels": ["2025-01-01", ...], "datasets": {"critical": [0, ...], "high": [...], ...}}
    """
    conn = _get_db(root)
    try:
        rows = conn.execute(
            """
            SELECT DATE(timestamp) as day, severity_breakdown
            FROM scan_history
            WHERE timestamp >= DATE('now', ?)
            ORDER BY day ASC
            """,
            (f"-{days} days",),
        ).fetchall()

        from collections import defaultdict

        daily: dict[str, dict[str, int]] = defaultdict(
            lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        )
        for day, sb_json in rows:
            sb = json.loads(sb_json or "{}")
            for sev in ("critical", "high", "medium", "low", "info"):
                daily[day][sev] += sb.get(sev, 0)

        labels = sorted(daily.keys())
        datasets = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            datasets[sev] = [daily[d][sev] for d in labels]
        return {"labels": labels, "datasets": datasets}
    finally:
        conn.close()


def patchi_get_health_scores(root: Path, days: int = 180) -> dict:
    """Health score over time for trend charts."""
    conn = _get_db(root)
    try:
        rows = conn.execute(
            """
            SELECT DATE(timestamp) as day, MAX(health_score) as score
            FROM scan_history
            WHERE timestamp >= DATE('now', ?)
            GROUP BY DATE(timestamp)
            ORDER BY day ASC
            """,
            (f"-{days} days",),
        ).fetchall()
        return {"labels": [r[0] for r in rows], "scores": [r[1] for r in rows]}
    finally:
        conn.close()


def patchi_get_metrics_history(root: Path, metric_key: str, days: int = 90) -> dict:
    """Extract a specific metric (e.g. coverage, bundle_size) over time."""
    conn = _get_db(root)
    try:
        rows = conn.execute(
            """
            SELECT DATE(timestamp) as day, metrics
            FROM scan_history
            WHERE timestamp >= DATE('now', ?) AND metrics != '{}'
            ORDER BY timestamp ASC
            """,
            (f"-{days} days",),
        ).fetchall()
        labels: list[str] = []
        values: list[float] = []
        for day, m_json in rows:
            m = json.loads(m_json or "{}")
            val = m.get(metric_key)
            if val is not None:
                labels.append(day)
                values.append(float(val))
        return {"labels": labels, "values": values}
    finally:
        conn.close()


def patchi_get_analytics(root: Path) -> dict:
    """Get trend analytics from scan history."""
    conn = _get_db(root)
    try:
        # Total scans
        total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]

        # Findings by status
        status_counts = {}
        for row in conn.execute("SELECT status, COUNT(*) FROM findings GROUP BY status"):
            status_counts[row[0]] = row[1]

        # Most common rule violations
        common_rules = []
        for row in conn.execute(
            "SELECT rule_id, COUNT(*) as cnt FROM findings WHERE rule_id != '' GROUP BY rule_id ORDER BY cnt DESC"
            " LIMIT 10"
        ):
            common_rules.append({"rule": row[0], "count": row[1]})

        # Average findings per scan
        avg_findings = 0
        if total > 0:
            total_findings = conn.execute("SELECT SUM(findings_count) FROM scan_history").fetchone()[0] or 0
            avg_findings = round(total_findings / total, 1)

        return {
            "total_scans": total,
            "findings_by_status": status_counts,
            "common_rules": common_rules,
            "avg_findings_per_scan": avg_findings,
        }
    finally:
        conn.close()


# ── History Agent ─────────────────────────────────────────────────────────────


@register
class HistoryAgent(BaseAgent):
    """Records scan results to SQLite history and provides analytics."""

    name = "HistoryAgent"
    group = AgentGroup.GUARD
    timeout = 30

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        history = patchi_get_history(inp.root, limit=5)
        analytics = patchi_get_analytics(inp.root)

        result.data["recent_scans"] = history
        result.data["analytics"] = analytics

        if analytics["total_scans"] == 0:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="no_scan_history",
                    severity=Severity.INFO,
                    file="",
                    message="No previous scan history found — this is the first scan",
                )
            )
