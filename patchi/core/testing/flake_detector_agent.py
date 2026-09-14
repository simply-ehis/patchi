"""FlakeDetectorAgent — tracks test results across runs to detect flaky tests.

Persists per-run test results (name, status, duration) to SQLite.
After N runs, queries history to find tests that pass/fail inconsistently
and tests with abnormal duration variance.

Language-agnostic: any test framework output that produces test names,
pass/fail status, and durations works here.
"""

from __future__ import annotations

import sqlite3
import statistics
import time
import uuid
from pathlib import Path

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    register,
)

_FLAKE_DB_NAME = "flake_history.db"
_MIN_RUNS_FOR_FLAKE = 2


def _get_flake_db(root: Path) -> sqlite3.Connection:
    db_path = root / ".patchi" / _FLAKE_DB_NAME
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10.0)
    # Part 8: bind busy_timeout so concurrent test-run writes queue
    # instead of failing with "database is locked".
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS test_runs (
            run_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            runner TEXT,
            total INT DEFAULT 0,
            passed INT DEFAULT 0,
            failed INT DEFAULT 0,
            skipped INT DEFAULT 0,
            duration_ms INT DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS test_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            test_name TEXT NOT NULL,
            passed INT NOT NULL,
            duration_ms INT DEFAULT 0,
            file TEXT DEFAULT '',
            line INT DEFAULT 0,
            FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
        );
        CREATE INDEX IF NOT EXISTS idx_test_results_name ON test_results(test_name);
    """)
    return conn


def _record_test_run(
    root: Path,
    runner: str,
    cases: list[dict],
    total: int,
    passed: int,
    failed: int,
    skipped: int,
    duration_ms: int,
) -> str:
    run_id = uuid.uuid4().hex[:12]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = _get_flake_db(root)
    try:
        conn.execute(
            "INSERT INTO test_runs (run_id, timestamp, runner, total, passed, failed, skipped, duration_ms) VALUES (?,"
            " ?, ?, ?, ?, ?, ?, ?)",
            (run_id, now, runner, total, passed, failed, skipped, duration_ms),
        )
        for c in cases:
            conn.execute(
                "INSERT INTO test_results (run_id, test_name, passed, duration_ms, file, line) VALUES (?, ?, ?, ?, ?,"
                " ?)",
                (
                    run_id,
                    c.get("name", "?"),
                    1 if c.get("passed", True) else 0,
                    c.get("duration_ms", 0),
                    c.get("file", ""),
                    c.get("line", 0),
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return run_id


def _get_all_runs(root: Path) -> list[dict]:
    conn = _get_flake_db(root)
    try:
        cur = conn.execute(
            "SELECT run_id, timestamp, runner, total, passed, failed, skipped, duration_ms FROM test_runs ORDER BY"
            " rowid ASC"
        )
        return [
            {
                "run_id": r[0],
                "timestamp": r[1],
                "runner": r[2],
                "total": r[3],
                "passed": r[4],
                "failed": r[5],
                "skipped": r[6],
                "duration_ms": r[7],
            }
            for r in cur.fetchall()
        ]
    finally:
        conn.close()


def _get_test_history(root: Path, test_name: str) -> list[dict]:
    conn = _get_flake_db(root)
    try:
        cur = conn.execute(
            "SELECT tr.run_id, tr.timestamp, res.passed, res.duration_ms, res.file, res.line "
            "FROM test_results res JOIN test_runs tr ON res.run_id = tr.run_id "
            "WHERE res.test_name = ? ORDER BY tr.rowid ASC",
            (test_name,),
        )
        return [
            {
                "run_id": r[0],
                "timestamp": r[1],
                "passed": bool(r[2]),
                "duration_ms": r[3],
                "file": r[4],
                "line": r[5],
            }
            for r in cur.fetchall()
        ]
    finally:
        conn.close()


def _get_all_test_names(root: Path) -> list[str]:
    conn = _get_flake_db(root)
    try:
        cur = conn.execute("SELECT DISTINCT test_name FROM test_results ORDER BY test_name")
        return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()


def _detect_flaky_tests(root: Path, min_runs: int = _MIN_RUNS_FOR_FLAKE) -> list[dict]:
    flakes: list[dict] = []
    for test_name in _get_all_test_names(root):
        history = _get_test_history(root, test_name)
        if len(history) < min_runs:
            continue
        outcomes = [h["passed"] for h in history]
        if len(set(outcomes)) > 1:
            flakes.append(
                {
                    "test_name": test_name,
                    "history": history,
                    "run_count": len(history),
                    "pass_count": sum(1 for h in history if h["passed"]),
                    "fail_count": sum(1 for h in history if not h["passed"]),
                    "latest_file": history[-1]["file"],
                    "latest_line": history[-1]["line"],
                }
            )
    return flakes


def _detect_duration_outliers(root: Path, z_threshold: float = 3.0) -> list[dict]:
    outliers: list[dict] = []
    for test_name in _get_all_test_names(root):
        history = _get_test_history(root, test_name)
        durations = [h["duration_ms"] for h in history if h["duration_ms"] > 0]
        if len(durations) < 3:
            continue
        mean = statistics.mean(durations)
        stdev = statistics.stdev(durations) if len(durations) > 1 else 0.0
        if stdev == 0:
            continue
        latest_dur = history[-1]["duration_ms"]
        z_score = (latest_dur - mean) / stdev
        if z_score > z_threshold:
            outliers.append(
                {
                    "test_name": test_name,
                    "mean_duration_ms": round(mean, 1),
                    "stdev_duration_ms": round(stdev, 1),
                    "latest_duration_ms": latest_dur,
                    "z_score": round(z_score, 2),
                    "history": history,
                    "latest_file": history[-1]["file"],
                    "latest_line": history[-1]["line"],
                }
            )
    return outliers


@register
class FlakeDetectorAgent(BaseAgent):
    """Detects flaky tests and duration regressions across multiple test runs."""

    group = AgentGroup.TEST
    domain = AgentDomain.TESTING
    name = "FlakeDetectorAgent"
    description = (
        "Track test results across runs to detect flaky tests "
        "(inconsistent pass/fail) and duration regressions. "
        "Language-agnostic: works with pytest, jest, mocha, unittest, go test, etc."
    )

    min_runs: int = 2

    def _run(self, inp: AgentInput, result: AgentResult) -> None:

        if not inp.root:
            result.status = AgentStatus.FAILED
            result.error = "No project root provided"
            return

        run_count = _get_all_runs(inp.root)
        result.data["total_runs"] = len(run_count)

        flakes = _detect_flaky_tests(inp.root, min_runs=self.min_runs)
        result.data["flaky_tests"] = len(flakes)
        result.data["flaky_details"] = flakes

        outliers = _detect_duration_outliers(inp.root, z_threshold=3.0)
        result.data["duration_outliers"] = len(outliers)
        result.data["duration_outlier_details"] = outliers

        for f in flakes:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="flaky_test",
                    severity=Severity.MEDIUM,
                    file=f.get("latest_file", ""),
                    line=f.get("latest_line", 0),
                    message=f"Flaky test: {f['test_name']}",
                    detail=(
                        f"Passed {f['pass_count']}/{f['run_count']} runs, "
                        f"failed {f['fail_count']}/{f['run_count']} runs."
                    ),
                )
            )

        for o in outliers:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="duration_regression",
                    severity=Severity.LOW,
                    file=o.get("latest_file", ""),
                    line=o.get("latest_line", 0),
                    message=f"Duration regression: {o['test_name']}",
                    detail=(
                        f"Latest run: {o['latest_duration_ms']}ms "
                        f"(mean {o['mean_duration_ms']}ms, "
                        f"z-score {o['z_score']})"
                    ),
                )
            )

        result.files_scanned = result.data["total_runs"]
        return


def record_test_run(
    root: Path,
    runner: str,
    cases: list[dict],
    total: int,
    passed: int,
    failed: int,
    skipped: int,
    duration_ms: int,
) -> str:
    """Public entry point for UnitTestAgent (or any caller) to record results.

    Returns the run_id.
    """
    return _record_test_run(root, runner, cases, total, passed, failed, skipped, duration_ms)
