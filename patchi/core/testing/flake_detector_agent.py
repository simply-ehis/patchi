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
# Retention window: history is implicitly windowed to the newest runs, so an
# ancient failure can't quarantine a test forever (audit: no un-quarantine
# path). Pruned on every record — one indexed DELETE pair, amortized.
_MAX_KEPT_RUNS = 50


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
        _prune_old_runs(conn)
    finally:
        conn.close()
    return run_id


def _prune_old_runs(conn: sqlite3.Connection, keep: int = _MAX_KEPT_RUNS) -> None:
    """Drop runs (and their results) older than the newest `keep`."""
    cur = conn.execute(
        "SELECT run_id FROM test_runs ORDER BY rowid DESC LIMIT -1 OFFSET ?",
        (keep,),
    )
    stale = [r[0] for r in cur.fetchall()]
    if not stale:
        return
    conn.execute(
        f"DELETE FROM test_results WHERE run_id IN ({','.join('?' * len(stale))})",
        stale,
    )
    conn.execute(
        f"DELETE FROM test_runs WHERE run_id IN ({','.join('?' * len(stale))})",
        stale,
    )
    conn.commit()


def _flake_rows(
    conn: sqlite3.Connection, min_runs: int
) -> list[tuple[str, int, int, int, str, int]]:
    """One aggregated query: (name, runs, passed, failed, latest file, line).

    Flaky = passed > 0 AND failed > 0. Single round-trip instead of the old
    names × per-test-history fan-out; full history is then fetched only for
    the (usually few) flaky names.
    """
    cur = conn.execute(
        "SELECT test_name, COUNT(*), COALESCE(SUM(passed), 0), MAX(rowid) "
        "FROM test_results GROUP BY test_name HAVING COUNT(*) >= ?",
        (min_runs,),
    )
    agg = [(r[0], r[1], r[2], r[3]) for r in cur.fetchall()]
    if not agg:
        return []
    latest = {
        r[0]: (r[1], r[2])
        for r in conn.execute(
            f"SELECT rowid, file, line FROM test_results WHERE rowid IN "
            f"({','.join('?' * len(agg))})",
            [a[3] for a in agg],
        ).fetchall()
    }
    out = []
    for name, runs, passed, max_rowid in agg:
        failed = runs - passed
        if passed > 0 and failed > 0:
            f, ln = latest.get(max_rowid, ("", 0))
            out.append((name, runs, passed, failed, f, ln))
    return out


def _histories_for(
    conn: sqlite3.Connection, names: list[str]
) -> dict[str, list[dict]]:
    """Full per-test history for exactly `names` (one query, grouped)."""
    if not names:
        return {}
    cur = conn.execute(
        "SELECT res.test_name, tr.run_id, tr.timestamp, res.passed, "
        "res.duration_ms, res.file, res.line "
        "FROM test_results res JOIN test_runs tr ON res.run_id = tr.run_id "
        f"WHERE res.test_name IN ({','.join('?' * len(names))}) "
        "ORDER BY tr.rowid ASC",
        names,
    )
    grouped: dict[str, list[dict]] = {n: [] for n in names}
    for r in cur.fetchall():
        grouped[r[0]].append(
            {
                "run_id": r[1],
                "timestamp": r[2],
                "passed": bool(r[3]),
                "duration_ms": r[4],
                "file": r[5],
                "line": r[6],
            }
        )
    return grouped


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
    conn = _get_flake_db(root)
    try:
        rows = _flake_rows(conn, min_runs)
        histories = _histories_for(conn, [r[0] for r in rows])
    finally:
        conn.close()
    return [
        {
            "test_name": name,
            "history": histories[name],
            "run_count": runs,
            "pass_count": passed,
            "fail_count": failed,
            "latest_file": latest_file,
            "latest_line": latest_line,
        }
        for name, runs, passed, failed, latest_file, latest_line in rows
    ]


def _detect_duration_outliers(root: Path, z_threshold: float = 3.0) -> list[dict]:
    # One connection, one ordered scan grouped in Python: same z-math as
    # before, without the names × per-test open/query/close fan-out.
    # (SQLite has no STDDEV aggregate, so the series still comes over.)
    conn = _get_flake_db(root)
    try:
        cur = conn.execute(
            "SELECT res.test_name, res.duration_ms, res.file, res.line "
            "FROM test_results res JOIN test_runs tr ON res.run_id = tr.run_id "
            "ORDER BY res.test_name, tr.rowid ASC"
        )
        series: dict[str, list[tuple[int, str, int]]] = {}
        for name, dur, f, ln in cur.fetchall():
            series.setdefault(name, []).append((dur, f, ln))
    finally:
        conn.close()
    outliers: list[dict] = []
    for test_name, rows in series.items():
        durations = [d for d, _, _ in rows if d > 0]
        if len(durations) < 3:
            continue
        mean = statistics.mean(durations)
        stdev = statistics.stdev(durations) if len(durations) > 1 else 0.0
        if stdev == 0:
            continue
        latest_dur, latest_file, latest_line = rows[-1]
        z_score = (latest_dur - mean) / stdev
        if z_score > z_threshold:
            outliers.append(
                {
                    "test_name": test_name,
                    "mean_duration_ms": round(mean, 1),
                    "stdev_duration_ms": round(stdev, 1),
                    "latest_duration_ms": latest_dur,
                    "z_score": round(z_score, 2),
                    "history": [
                        {"duration_ms": d, "file": f, "line": ln} for d, f, ln in rows
                    ],
                    "latest_file": latest_file,
                    "latest_line": latest_line,
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


def get_quarantined_tests(root: Path, flake_threshold: float = 0.5) -> set[str]:
    """Return test names that should be auto-quarantined (skipped).

    A test is quarantined if it has flaked in >= flake_threshold fraction of
    its runs (default 50%). Quarantined tests are recorded in a separate table
    so they can be reviewed and manually un-quarantined.
    """
    quarantined: set[str] = set()
    conn = _get_flake_db(root)
    try:
        # Ensure the quarantine table exists
        conn.execute("""
            CREATE TABLE IF NOT EXISTS quarantined_tests (
                test_name TEXT PRIMARY KEY,
                quarantined_at TEXT NOT NULL,
                reason TEXT DEFAULT 'auto-flake',
                flake_rate REAL DEFAULT 0.0
            )
        """)
        conn.commit()

        # Flaky candidates from one aggregated query (windowed by retention:
        # only the newest _MAX_KEPT_RUNS runs exist to flip).
        for test_name, runs, passed, failed, _f, _ln in _flake_rows(conn, _MIN_RUNS_FOR_FLAKE):
            fail_rate = failed / runs
            if fail_rate >= flake_threshold:
                quarantined.add(test_name)
                conn.execute(
                    "INSERT OR REPLACE INTO quarantined_tests (test_name, quarantined_at, reason, flake_rate)"
                    " VALUES (?, ?, ?, ?)",
                    (test_name, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "auto-flake", fail_rate),
                )
        conn.commit()
    finally:
        conn.close()
    return quarantined
