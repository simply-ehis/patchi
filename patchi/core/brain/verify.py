"""
Self-Report Verifier (Dream Assistant spec — Live/Audit Mode, priority #1).

The whole point: don't trust the agent's "tests pass" / "this works" claim.
Independently re-run the project's real test suite (and optionally a scan),
compare against the last known-good baseline, and emit an authoritative,
plain-language truth report.

Usage:
  p verify                 — re-run tests (+ scan), diff against baseline, report truth
  p verify --no-scan      — only re-run tests
  p verify --claim "tests pass"   — assert a specific claim against actual truth

This reuses the project's own test runner (pytest by default) and Patchi's
Brain scan — it never trusts a self-report.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

_BASELINE_FILE = ".patchi/verify_baseline.json"


import logging

_log = logging.getLogger("patchi.brain.verify")


@dataclass
class TestRun:
    __test__ = False  # tell pytest this is not a test class
    command: str = ""
    passed: int = 0
    failed: int = 0
    error: int = 0
    skipped: int = 0
    total: int = 0
    failed_names: list[str] = field(default_factory=list)
    raw: str = ""
    exit_ok: bool = False
    duration_seconds: float = 0.0
    note: str = ""

    @property
    def truthful(self) -> bool:
        """True only if the suite actually ran and nothing failed/errored."""
        return bool(self.command) and self.exit_ok and self.failed == 0 and self.error == 0


@dataclass
class VerifyReport:
    __test__ = False
    scanned_at: str = ""
    test_run: TestRun | None = None
    findings_count: int = 0
    charter_violations: int = 0
    scan_error: str | None = None
    baseline: dict | None = None
    regression: dict | None = None
    truthful: bool = False
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "scanned_at": self.scanned_at,
            "truthful": self.truthful,
            "tests": {
                "passed": self.test_run.passed if self.test_run else 0,
                "failed": self.test_run.failed if self.test_run else 0,
                "error": self.test_run.error if self.test_run else 0,
                "skipped": self.test_run.skipped if self.test_run else 0,
                "truthful": self.test_run.truthful if self.test_run else False,
            },
            "findings_count": self.findings_count,
            "charter_violations": self.charter_violations,
            "regression": self.regression,
            "summary": self.summary,
        }


# ── Test runner ────────────────────────────────────────────────────────────────


def detect_test_command(root: Path) -> str | None:
    """Pick the project's real test runner. Prefer pytest; fall back to unittest."""
    if shutil.which("pytest"):
        return "pytest -q -p no:cacheprovider"
    return "python -m unittest discover -s tests -v"


def run_tests(root: Path, command: str | None = None) -> TestRun:
    """Independently execute the project's test suite. Never trusts a claim."""
    cmd = command or detect_test_command(root)
    if not cmd:
        return TestRun(note="No test runner (pytest/unittest) found.")
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd.split(),
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except Exception as e:  # pragma: no cover - environment dependent
        return TestRun(command=cmd, note=f"Could not run tests: {e}")
    raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
    dur = time.monotonic() - start
    run = _parse_pytest_output(raw)
    run.command = cmd
    run.raw = raw
    run.exit_ok = proc.returncode == 0
    run.duration_seconds = round(dur, 2)
    if not run.total and "no tests ran" in raw:
        run.note = "No tests found."
    return run


def _parse_pytest_output(text: str) -> TestRun:
    run = TestRun()
    for metric, attr in (
        ("passed", "passed"),
        ("failed", "failed"),
        ("error", "error"),
        ("skipped", "skipped"),
    ):
        m = re.search(rf"(\d+)\s+{metric}", text)
        if m:
            setattr(run, attr, int(m.group(1)))
    run.total = run.passed + run.failed + run.error + run.skipped
    run.failed_names = re.findall(r"FAILED\s+([^\s-]+)", text)
    return run


# ── Baseline (regression radar) ───────────────────────────────────────────────────


def _baseline_path(root: Path) -> Path:
    return root / _BASELINE_FILE


def load_baseline(root: Path) -> dict | None:
    p = _baseline_path(root)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        _log.warning("load_baseline failed: %s", e)
        return None


def save_baseline(root: Path, snapshot: dict) -> None:
    p = _baseline_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    tmp.replace(p)


def compute_regression(
    baseline: dict | None,
    test_run: TestRun,
    findings_count: int,
    charter_violations: int,
) -> dict:
    """Diff current truth against the last known-good baseline."""
    if not baseline:
        return {
            "has_baseline": False,
            "new_failures": list(test_run.failed_names),
            "new_findings": findings_count,
            "new_charter_violations": charter_violations,
        }
    base_fail = set(baseline.get("failed_names", []))
    cur_fail = set(test_run.failed_names)
    base_find = baseline.get("findings_count", 0)
    base_charter = baseline.get("charter_violations", 0)
    return {
        "has_baseline": True,
        "new_failures": sorted(cur_fail - base_fail),
        "resolved_failures": sorted(base_fail - cur_fail),
        "new_findings": max(0, findings_count - base_find),
        "new_charter_violations": max(0, charter_violations - base_charter),
    }


# ── Verify orchestration ─────────────────────────────────────────────────────────


def verify_project(
    root: Path,
    test_runner=None,
    run_scan: bool = True,
) -> VerifyReport:
    """
    Independently verify the project's actual state.

    test_runner: injectable for tests; defaults to run_tests().
    Returns a VerifyReport with an authoritative truth + regression delta.
    """
    root = Path(root)
    test_run = (test_runner or run_tests)(root)

    findings_count = 0
    charter_violations = 0
    scan_error = None
    if run_scan:
        try:
            from patchi.core.brain.brain import Brain

            Brain(root).scan()
            findings_count = _count_scan_findings(root)
            charter_violations = _count_charter_violations(root)
        except Exception as e:
            scan_error = str(e)

    baseline = load_baseline(root)
    regression = compute_regression(baseline, test_run, findings_count, charter_violations)

    truthful = test_run.truthful and not regression.get("new_failures") and charter_violations == 0

    save_baseline(
        root,
        {
            "scanned_at": datetime.now(UTC).isoformat(),
            "failed_names": test_run.failed_names,
            "findings_count": findings_count,
            "charter_violations": charter_violations,
        },
    )

    summary = _build_summary(truthful, test_run, regression, charter_violations, scan_error)
    return VerifyReport(
        scanned_at=datetime.now(UTC).isoformat(),
        test_run=test_run,
        findings_count=findings_count,
        charter_violations=charter_violations,
        scan_error=scan_error,
        baseline=baseline,
        regression=regression,
        truthful=truthful,
        summary=summary,
    )


def _count_scan_findings(root: Path) -> int:
    """Count findings from the most recent scan results in memory."""
    try:
        from patchi.core import memory as mem

        results = mem.get_scan_results(root)
        total = 0
        for _name, data in results.items():
            for f in data.get("findings", []):
                if isinstance(f, dict):
                    total += 1
        return total
    except Exception as e:
        _log.warning("_count_scan_findings failed: %s", e)
        return 0


def _count_charter_violations(root: Path) -> int:
    try:
        from patchi.core import memory as mem

        results = mem.get_scan_results(root)
        return len(results.get("CharterGuard", {}).get("findings", []))
    except Exception as e:
        _log.warning("_count_charter_violations failed: %s", e)
        return 0


def _build_summary(truthful, test_run, regression, charter_violations, scan_error) -> str:
    if truthful:
        return (
            f"VERIFIED ✅ — tests: {test_run.passed} passed"
            + (f", {test_run.skipped} skipped" if test_run.skipped else "")
            + (
                f"; {regression.get('new_findings', 0)} new scan finding(s)"
                if regression.get("new_findings")
                else "; no new scan findings"
            )
            + "."
        )
    parts = ["UNVERIFIED ❌ — mismatch between claim and reality:"]
    if not test_run.truthful:
        parts.append(
            f"  • tests: {test_run.failed} failed, {test_run.error} errored"
            + (f" -> {', '.join(test_run.failed_names[:5])}" if test_run.failed_names else "")
        )
    if regression.get("new_failures"):
        parts.append(f"  • new failures vs baseline: {', '.join(regression['new_failures'][:5])}")
    if charter_violations:
        parts.append(f"  • {charter_violations} charter violation(s)")
    if scan_error:
        parts.append(f"  • scan could not run: {scan_error}")
    return "\n".join(parts)


def claim_holds(claim: str, report: VerifyReport) -> bool:
    """Crude claim check: 'tests pass' / 'works' must match an actually truthful run."""
    low = claim.lower()
    if "pass" in low or "works" in low or "green" in low:
        return report.truthful
    return report.truthful
