"""
Patchi Health Score — single 0–100 number computed from scan data.

Formula (Section 13 of spec):
  Security posture     35%  — findings severity weighted, secret count, vuln deps
  Test coverage        25%  — % of source files with a test counterpart
  Dead code ratio      20%  — % of files that are confirmed dead
  Dependency health    10%  — % of deps with no known CVE
  App contract         10%  — % of contract flows confirmed (0 if no contract yet)

Score interpretation:
  90–100  Excellent  (green)
  70–89   Good       (yellow-green)
  50–69   Fair       (yellow)
  30–49   Poor       (orange)
  0–29    Critical   (red)

The score is computed from brain memory + agent scan results.
It is saved back to brain memory after every scan so `p status` can display it.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from patchi.core import memory as mem

_log = logging.getLogger("patchi.core.health")

# In-process cache: recompute at most every N seconds so dashboard requests
# stay fast.  Scan completion bumps the timestamp so fresh data shows quickly.
_HEALTH_TTL = 30.0
_health_cache: dict = {}
_health_lock = threading.Lock()


def invalidate_cache() -> None:
    """Force next compute() to re-run (call after a scan completes)."""
    with _health_lock:
        _health_cache.clear()


@dataclass
class HealthScore:
    total: int  # 0–100
    security: float  # component raw score 0–100
    test_coverage: float
    dead_code: float
    dependency: float
    contract: float
    grade: str  # A / B / C / D / F
    color: str  # rich color string
    breakdown: dict  # per-component detail

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "grade": self.grade,
            "color": self.color,
            "components": {
                "security": round(self.security, 1),
                "test_coverage": round(self.test_coverage, 1),
                "dead_code": round(self.dead_code, 1),
                "dependency": round(self.dependency, 1),
                "contract": round(self.contract, 1),
            },
            "breakdown": self.breakdown,
        }


# ── Weights ────────────────────────────────────────────────────────────────────

_WEIGHTS = {
    "security": 0.35,
    "test_coverage": 0.25,
    "dead_code": 0.20,
    "dependency": 0.10,
    "contract": 0.10,
}


# ── Main compute function ──────────────────────────────────────────────────────


def compute(root: Path | None = None) -> HealthScore:
    """
    Compute the health score from brain memory and agent scan results.
    Returns a HealthScore with all components filled.
    Results are cached in-process for _HEALTH_TTL seconds — the dashboard
    calls this on every request, and a full recompute is expensive.
    """
    key = str(root) if root is not None else ""
    now = time.time()
    with _health_lock:
        cached = _health_cache.get(key)
        if cached and (now - cached[0]) < _HEALTH_TTL:
            return cached[1]

    brain = mem.get_brain(root)
    scans = mem.get_scan_results(root)
    patches = mem.list_patches(root)

    security = _compute_security(brain, scans)
    test_coverage_pct = _compute_test_coverage_pct(root, brain)
    test_coverage = _compute_test_coverage(brain, scans, test_coverage_pct)
    dead_code = _compute_dead_code(brain, scans)
    dependency = _compute_dependency(brain, scans)
    contract = _compute_contract(brain)

    raw = (
        security * _WEIGHTS["security"]
        + test_coverage * _WEIGHTS["test_coverage"]
        + dead_code * _WEIGHTS["dead_code"]
        + dependency * _WEIGHTS["dependency"]
        + contract * _WEIGHTS["contract"]
    )

    total = max(0, min(100, round(raw)))
    grade, color = _grade(total)

    score = HealthScore(
        total=total,
        security=security,
        test_coverage=test_coverage,
        dead_code=dead_code,
        dependency=dependency,
        contract=contract,
        grade=grade,
        color=color,
        breakdown=_build_breakdown(brain, scans, patches, test_coverage_pct),
    )

    # Save to brain memory so `p status` can display it without rescanning
    try:
        brain["health_score"] = score.to_dict()
        brain["test_coverage_pct"] = test_coverage_pct
        mem.save_brain(brain, root)
    except Exception as e:
        _log.warning("Failed to save health score to brain: %s", e)

    # Persist health score to scan history for trend charts (WIRE-07)
    if root is not None:
        try:
            from patchi.core.security.history import patchi_record_scan

            patchi_record_scan(root, tool="health_compute", findings=[], health_score=total)
        except Exception as e:
            _log.warning("Failed to record health score to history: %s", e)

    with _health_lock:
        _health_cache[key] = (time.time(), score)

    return score


# ── Component computers ────────────────────────────────────────────────────────


def _compute_security(brain: dict, scans: dict) -> float:
    """
    Security score (0-100).
    Deductions:
      CRITICAL finding  -20 (capped at -60 total)
      HIGH finding      -10 (capped at -30 total)
      MEDIUM finding    -3
      Hardcoded secret  -25 (per secret, heavy)
      Unprotected route -8 (per route)
      Injection vuln    -15 (per finding, capped at -30)
      Crypto issue      -5 (per finding, capped at -15)
      AuthZ issue       -10 (per finding, capped at -20)
    """
    score = 100.0
    env_data = scans.get("EnvScanner", {})
    route_data = scans.get("RouteGraphScanner", {})

    secret_count = env_data.get("finding_count", 0)
    score -= min(secret_count * 25, 60)

    unprotected = route_data.get("finding_count", 0)
    score -= min(unprotected * 8, 32)

    circular = len(brain.get("circular_deps", []))
    score -= min(circular * 2, 10)

    security_agents = [
        "TaintAnalyzer",
        "SecretScanner",
        "ConfigAuditAgent",
        "HeaderAuditAgent",
        "RateLimitAuditor",
        "CORSAuditor",
        "DependencyCVEChecker",
        "MisconfigAgent",
        "JWTSecurityAgent",
        "SensitiveDataAgent",
        "AuthenticationAuditAgent",
        "SSRFProtectionAgent",
        "InjectionAgent",
        "AuthZAgent",
        "CryptoAgent",
        "NetworkAgent",
        "PrivacyAgent",
        "DependencyVulnerabilityAgent",
        "ComplianceAgent",
    ]

    crit_deductions = 0
    high_deductions = 0
    med_deductions = 0

    # Part 3 §2.5: "0 findings because the tool is missing" is not the same
    # fact as "0 findings because nothing is wrong". A security agent skipped
    # for a missing tool costs a little confidence instead of counting as a
    # clean pass (capped so a fresh install can't zero out the score).
    tools_missing = 0
    for agent_name in security_agents:
        if (scans.get(agent_name, {}) or {}).get("tool_missing"):
            tools_missing += 1
    score -= min(tools_missing * 2, 15)

    for agent_name in security_agents:
        agent_data = scans.get(agent_name, {})
        for f in agent_data.get("findings", []):
            sev = f.get("severity", "info")
            if sev == "critical":
                crit_deductions += 20
            elif sev == "high":
                high_deductions += 10
            elif sev == "medium":
                med_deductions += 3

    score -= min(crit_deductions, 60)
    score -= min(high_deductions, 30)
    score -= med_deductions

    return max(0.0, score)


def _compute_test_coverage(brain: dict, scans: dict, real_pct: float = 0.0) -> float:
    """Test coverage score from TestScanner coverage_pct, with real % as fallback.

    §2d honesty fix: a project with ZERO tests must not borrow the neutral
    50.0 default that "unknown coverage" used to get — reporting 0 tests the
    same as half-covered is exactly the false-confidence signal the health
    score exists to prevent. Zero coverage now scores 0.
    """
    test_data = scans.get("TestScanner", {})
    pct = test_data.get("coverage_pct")
    if pct is not None:
        return float(pct)
    return real_pct


def _compute_dead_code(brain: dict, scans: dict) -> float:
    """
    Dead code score (0-100).
    100 = no dead code. Deduction per dead file.
    """
    dead_data = scans.get("DeadCodeScanner", {})
    file_count = brain.get("file_count", 1) or 1

    confirmed = len(dead_data.get("confirmed_dead", []))
    broken = len(dead_data.get("broken_import", []))
    total_dead = confirmed + (broken * 0.5)

    dead_ratio = min(total_dead / file_count, 1.0)
    score = 100 - (dead_ratio * 100)
    return max(0.0, min(100.0, score))


def _compute_dependency(brain: dict, scans: dict) -> float:
    """
    Dependency health: 100 = all clean. Score drops with ratio of vulnerable deps.
    """
    dep_data = scans.get("DependencyScanner", {})
    total = dep_data.get("total_deps", 0)
    vulnerable = len(dep_data.get("vulnerable", []))

    if total == 0:
        return 80.0

    ratio = vulnerable / total
    score = 100 - (ratio * 150)
    return max(0.0, min(100.0, score))


def _compute_contract(brain: dict) -> float:
    """
    Contract score: 100 = all flows confirmed. 0 = no contract established yet.
    Partial: (confirmed / inferred) * 100
    """
    inferred = brain.get("inferred_flows", [])
    confirmed = brain.get("confirmed_flows", [])

    # Re-key retired ids before the ratio: orphan confirmations otherwise
    # inflate the score (confirmed ids infer() can never emit).
    try:
        from patchi.core.brain.contract import migrate_flow_dicts

        confirmed = migrate_flow_dicts(confirmed)
    except Exception as exc:
        _log.debug("contract health migration skipped: %s", exc)

    if not inferred:
        return 50.0

    if not confirmed:
        return 20.0

    ratio = len(confirmed) / len(inferred)
    return min(100.0, ratio * 100)


# ── Test coverage percentage ─────────────────────────────────────────────────


def _compute_test_coverage_pct(root: Path | None, brain: dict) -> float:
    """Count source files with test counterparts and return percentage.

    Same semantics as the original implementation (a source file is covered
    only by a test co-located in its own directory or a sibling tests/
    directory) but implemented as set lookups instead of per-file stat
    probes — that probe storm made this the dashboard's #1 bottleneck (~3.8s).
    """
    if root is None:
        return 0.0

    file_count = brain.get("file_count", 0)
    if file_count == 0:
        return 0.0

    source_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".rs", ".java"}
    test_patterns = ("test_", "_test.", ".test.", ".spec.", "_spec.")
    test_dirs = ("tests", "test", "__tests__", "spec")

    try:
        from patchi.core.agents.base import safe_rglob

        # Pass 1 — walk the tree once, collecting existing test names and
        # all source files.  No per-file stat() calls.
        src_by_dir: dict = {}
        test_names_by_dir: dict = {}
        for ext in source_extensions:
            for f in safe_rglob(root, f"*{ext}"):
                rel = f.relative_to(root).as_posix()
                parts = Path(rel).parts
                fname = f.name.lower()

                in_test_dir = any(p.lower() in test_dirs for p in parts)
                is_test_file = any(pat in fname for pat in test_patterns)
                dir_key = str(f.parent)

                if in_test_dir or is_test_file:
                    test_names_by_dir.setdefault(dir_key, set()).add(fname)
                else:
                    src_by_dir.setdefault(dir_key, []).append(f)

        source_files = 0
        files_with_tests = 0

        for dir_key, files in src_by_dir.items():
            own_tests = test_names_by_dir.get(dir_key, set())
            parent = Path(dir_key)
            sibling_tests = set()
            for td in test_dirs:
                sibling_tests |= test_names_by_dir.get(str(parent / td), set())

            for f in files:
                source_files += 1
                stem = f.stem
                candidates = (
                    {f"test_{stem}{ext}".lower() for ext in source_extensions}
                    | {f"{stem}_test{ext}".lower() for ext in source_extensions}
                    | {f"{stem}.test{ext}".lower() for ext in source_extensions}
                    | {f"{stem}.spec{ext}".lower() for ext in source_extensions}
                )
                if candidates & own_tests or candidates & sibling_tests:
                    files_with_tests += 1

        if source_files == 0:
            return 0.0

        return round((files_with_tests / source_files) * 100, 1)
    except Exception as e:
        _log.warning("_compute_test_coverage_pct failed: %s", e)
        return 0.0


# ── Grade + color ──────────────────────────────────────────────────────────────


def _grade(score: int) -> tuple[str, str]:
    if score >= 90:
        return "A", "#4ADE80"
    if score >= 70:
        return "B", "#86EFAC"
    if score >= 50:
        return "C", "#FACC15"
    if score >= 30:
        return "D", "#FB923C"
    return "F", "#FF4D6D"


# ── Breakdown detail ───────────────────────────────────────────────────────────


def _build_breakdown(brain: dict, scans: dict, patches: list, test_coverage_pct: float = 0.0) -> dict:
    return {
        "file_count": brain.get("file_count", 0),
        "route_count": brain.get("route_count", 0),
        "framework": brain.get("framework", "Unknown"),
        "circular_deps": len(brain.get("circular_deps", [])),
        "patches_applied": len(patches),
        "last_scan": brain.get("last_scan", ""),
        "agents_run": list(scans.keys()),
        "test_coverage_pct": test_coverage_pct,
    }
