"""SnapshotDriftDetectorAgent — detects UI snapshot changes and visual drift.

Covers §6.2.1:
- Monitor *.snap files (Jest snapshot files) for changes across runs
- Track baseline snapshot hashes in SQLite
- Alert when snapshots change (drift) between runs
- Flag unreviewed snapshot updates
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
import uuid
from pathlib import Path

from ..brain.languages import DEFAULT_IGNORE_DIRS
from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_SNAP_DB_NAME = "snapshot_drift.db"


def _get_snap_db(root: Path) -> sqlite3.Connection:
    db_path = root / ".patchi" / _SNAP_DB_NAME
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10.0)
    # Part 8: bind busy_timeout so concurrent snapshot writes queue
    # instead of failing with "database is locked".
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS snapshot_baselines (
            file_path TEXT PRIMARY KEY,
            hash TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS snapshot_drifts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            file_path TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            detected_at TEXT
        );
    """)
    return conn


def _hash_file(file_path: Path) -> str:
    return hashlib.sha256(file_path.read_bytes()).hexdigest()[:16]


@register
class SnapshotDriftDetectorAgent(BaseAgent):
    """Detects UI snapshot changes (Jest snapshots, storyshots) across runs."""

    group = AgentGroup.SCANNER
    name = "SnapshotDriftDetectorAgent"
    description = "Track snapshot file hashes across runs and alert on unexpected drift"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        run_id = uuid.uuid4().hex[:12]
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        drifts: list[dict] = []
        files_scanned = 0

        conn = _get_snap_db(inp.root)
        try:
            for fp in safe_rglob(inp.root, "*.snap"):
                rel = fp.relative_to(inp.root).as_posix()
                if any(seg in DEFAULT_IGNORE_DIRS for seg in Path(rel).parts):
                    continue
                files_scanned += 1
                current_hash = _hash_file(fp)

                row = conn.execute("SELECT hash FROM snapshot_baselines WHERE file_path = ?", (rel,)).fetchone()

                if row:
                    old_hash = row[0]
                    if current_hash != old_hash:
                        drifts.append(
                            {
                                "file": rel,
                                "old_hash": old_hash,
                                "new_hash": current_hash,
                            }
                        )
                        conn.execute(
                            "INSERT INTO snapshot_drifts (run_id, file_path, old_hash, new_hash, detected_at) VALUES"
                            " (?, ?, ?, ?, ?)",
                            (run_id, rel, old_hash, current_hash, now),
                        )
                else:
                    # New snapshot — record baseline
                    pass

                conn.execute(
                    "INSERT OR REPLACE INTO snapshot_baselines (file_path, hash, first_seen, last_seen) VALUES (?, ?,"
                    " COALESCE((SELECT first_seen FROM snapshot_baselines WHERE file_path = ?), ?), ?)",
                    (rel, current_hash, rel, now, now),
                )

            conn.commit()

        finally:
            conn.close()

        result.data["snapshot_files"] = files_scanned
        result.data["drifts"] = drifts
        result.data["total_drifts"] = len(drifts)
        result.files_scanned = files_scanned

        for d in drifts:
            result.findings.append(
                make_finding(
                    self.name,
                    "snapshot_drift",
                    Severity.MEDIUM,
                    d["file"],
                    f"Snapshot drift detected: {d['file']}",
                    detail="Snapshot hash changed since last scan. Review the changes.",
                    suggestion="Run `npm test -- -u` to update snapshots after verifying changes",
                )
            )

        if files_scanned == 0:
            result.findings.append(
                make_finding(
                    self.name,
                    "no_snapshots",
                    Severity.INFO,
                    "",
                    "No .snap files found — snapshot drift tracking not applicable",
                )
            )

        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
