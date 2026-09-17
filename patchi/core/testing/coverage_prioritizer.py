"""
Coverage-guided test prioritization (testing-security-moat-spec §6).

Ranks test files so that tests covering changed files and low-coverage critical
paths run first — fail-fast feedback in CI and local dev.

Usage:
    from patchi.core.testing.coverage_prioritizer import CoveragePrioritizer

    prioritizer = CoveragePrioritizer(root)
    coverage = prioritizer.collect_coverage()
    ranked = prioritizer.prioritize_tests(coverage, changed_files=["src/core.py"])
"""

from __future__ import annotations

import ast
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from patchi.core.constants import PATCHI_DIR

_log = logging.getLogger("patchi.testing.coverage_prioritizer")

_COVERAGE_CACHE = f"{PATCHI_DIR}/coverage_cache.json"
_COVERAGE_JSON = "coverage.json"

# Directories never containing project tests. Pruned DURING the walk (not
# filtered after) so node_modules/.git/.venv never pay stat() costs.
# Shared with scan_cmd's banner via test_stems_from_paths / iter_test_files.
SKIP_DIRS = frozenset({
    "__pycache__",
    ".patchi",
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
})


def iter_test_files(root: Path) -> Any:
    """Yield test_*.py paths relative to root, pruning SKIP_DIRS in-walk."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.startswith("test_") and fn.endswith(".py"):
                yield str((Path(dirpath) / fn).relative_to(root)).replace("\\", "/")


def test_stems_from_paths(paths: Any) -> set[str]:
    """Normalized test stems from relative paths (pure, no I/O).

    Single implementation behind the banner and the prioritizer so the two
    can never drift: test_foo.py → foo. __pycache__/.patchi excluded.
    """
    stems: set[str] = set()
    for p in paths:
        rel = str(p).replace("\\", "/")
        parts = rel.split("/")
        if "__pycache__" in parts or ".patchi" in parts:
            continue
        base = parts[-1]
        if base.startswith("test_") and base.endswith(".py"):
            stems.add(base[len("test_") : -len(".py")].lower())
    return stems


# ── Data classes ───────────────────────────────────────────────────────────────


@dataclass
class FunctionCoverage:
    """Coverage data for a single function."""

    name: str
    file: str
    lineno: int
    executed: bool
    branch_covered: bool | None = None


@dataclass
class FileCoverage:
    """Per-file coverage summary."""

    path: str
    statement_coverage: float  # 0.0–1.0
    branch_coverage: float = 0.0  # 0.0–1.0
    executed_statements: int = 0
    total_statements: int = 0
    executed_branches: int = 0
    total_branches: int = 0
    functions: list[FunctionCoverage] = field(default_factory=list)


@dataclass
class CoverageData:
    """Aggregated coverage data from a pytest --cov run."""

    total_statement_coverage: float = 0.0
    total_branch_coverage: float = 0.0
    files: dict[str, FileCoverage] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass
class PrioritizedTest:
    """A test file with its priority ranking."""

    test_file: str
    priority_score: float  # higher = run first
    covers_changed_files: bool = False
    covers_low_coverage: bool = False
    covers_critical_paths: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class UncoveredPath:
    """A critical function with zero coverage."""

    function_name: str
    file: str
    line: int
    fan_in: int  # number of files that import this function's module
    in_routes: bool = False


# ── Coverage collection ────────────────────────────────────────────────────────


def _parse_coverage_json(path: Path) -> CoverageData | None:
    """Parse coverage.json output from ``coverage json``."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        _log.debug("Failed to parse %s: %s", path, exc)
        return None

    files_dict: dict[str, FileCoverage] = {}
    totals = raw.get("totals", {})
    files_raw = raw.get("files", {})

    for fpath, fdata in files_raw.items():
        summary = fdata.get("summary", {})
        executed_stmts = summary.get("covered_lines", 0)
        total_stmts = summary.get("num_statements", 0)
        exec_branches = summary.get("covered_branches", 0)
        total_branches = summary.get("num_branches", 0)

        stmt_cov = (executed_stmts / total_stmts) if total_stmts else 0.0
        br_cov = (exec_branches / total_branches) if total_branches else 0.0

        funcs: list[FunctionCoverage] = []
        for fn in fdata.get("functions", []):
            funcs.append(
                FunctionCoverage(
                    name=fn.get("name", "<unknown>"),
                    file=fpath,
                    lineno=fn.get("lineno", 0),
                    executed=fn.get("execution_count", 0) > 0,
                )
            )

        files_dict[fpath] = FileCoverage(
            path=fpath,
            statement_coverage=round(stmt_cov, 4),
            branch_coverage=round(br_cov, 4),
            executed_statements=executed_stmts,
            total_statements=total_stmts,
            executed_branches=exec_branches,
            total_branches=total_branches,
            functions=funcs,
        )

    total_stmt = totals.get("covered_lines", 0)
    total_num = totals.get("num_statements", 1)
    total_br = totals.get("covered_branches", 0)
    total_br_num = totals.get("num_branches", 1)

    import time

    return CoverageData(
        total_statement_coverage=round(total_stmt / total_num, 4) if total_num else 0.0,
        total_branch_coverage=round(total_br / total_br_num, 4) if total_br_num else 0.0,
        files=files_dict,
        timestamp=time.time(),
    )


def _read_raw_coverage(path: Path) -> CoverageData | None:
    """Try to read a .coverage SQLite or coverage.json file."""
    # Prefer coverage.json if present (already exported)
    json_path = path.parent / _COVERAGE_JSON
    if json_path.exists():
        return _parse_coverage_json(json_path)

    # Try the .coverage file (SQLite) — we'd need coverage lib to read it,
    # so attempt a subprocess call to ``coverage json`` to export first.
    cov_file = path.parent / ".coverage"
    if cov_file.exists():
        return _export_and_parse(cov_file.parent)

    return None


def _export_and_parse(project_root: Path) -> CoverageData | None:
    """Run ``coverage json`` to export .coverage → coverage.json, then parse."""
    json_out = project_root / _COVERAGE_JSON
    try:
        subprocess.run(
            [sys.executable, "-m", "coverage", "json", "-o", str(json_out), "--pretty-print"],
            cwd=str(project_root),
            capture_output=True,
            timeout=30,
            check=False,
        )
        if json_out.exists():
            return _parse_coverage_json(json_out)
    except Exception as exc:
        _log.debug("coverage json export failed: %s", exc)
    return None


def _run_pytest_cov(project_root: Path) -> CoverageData | None:
    """Run ``pytest --cov --cov-report=json`` and parse the result."""
    json_out = project_root / _COVERAGE_JSON
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--cov",
                "--cov-report",
                f"json:{json_out}",
                "--tb=short",
                "-q",
            ],
            cwd=str(project_root),
            capture_output=True,
            timeout=300,
            check=False,
        )
        if json_out.exists():
            return _parse_coverage_json(json_out)
    except Exception as exc:
        _log.debug("pytest --cov failed: %s", exc)
    return None


# ── Cache ──────────────────────────────────────────────────────────────────────


def _cache_path(root: Path) -> Path:
    return root / _COVERAGE_CACHE


def _load_cache(root: Path) -> CoverageData | None:
    """Load cached coverage if .coverage / coverage.json hasn't changed."""
    cache = _cache_path(root)
    if not cache.exists():
        return None
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    # Check mtime: invalidate if .coverage or coverage.json is newer
    cov_sources = [root / ".coverage", root / _COVERAGE_JSON]
    cache_mtime = cache.stat().st_mtime
    for src in cov_sources:
        if src.exists() and src.stat().st_mtime > cache_mtime:
            return None  # stale — re-collect

    files_dict: dict[str, FileCoverage] = {}
    for fpath, fdata in data.get("files", {}).items():
        funcs = [
            FunctionCoverage(
                name=fn["name"],
                file=fn["file"],
                lineno=fn["lineno"],
                executed=fn["executed"],
                branch_covered=fn.get("branch_covered"),
            )
            for fn in fdata.get("functions", [])
        ]
        files_dict[fpath] = FileCoverage(
            path=fpath,
            statement_coverage=fdata.get("statement_coverage", 0.0),
            branch_coverage=fdata.get("branch_coverage", 0.0),
            executed_statements=fdata.get("executed_statements", 0),
            total_statements=fdata.get("total_statements", 0),
            executed_branches=fdata.get("executed_branches", 0),
            total_branches=fdata.get("total_branches", 0),
            functions=funcs,
        )

    return CoverageData(
        total_statement_coverage=data.get("total_statement_coverage", 0.0),
        total_branch_coverage=data.get("total_branch_coverage", 0.0),
        files=files_dict,
        timestamp=data.get("timestamp", 0.0),
    )


def _save_cache(root: Path, coverage: CoverageData) -> None:
    """Persist coverage data to the cache file."""
    cache = _cache_path(root)
    cache.parent.mkdir(parents=True, exist_ok=True)

    files_ser: dict[str, Any] = {}
    for fpath, fc in coverage.files.items():
        funcs = [
            {
                "name": fn.name,
                "file": fn.file,
                "lineno": fn.lineno,
                "executed": fn.executed,
                "branch_covered": fn.branch_covered,
            }
            for fn in fc.functions
        ]
        files_ser[fpath] = {
            "statement_coverage": fc.statement_coverage,
            "branch_coverage": fc.branch_coverage,
            "executed_statements": fc.executed_statements,
            "total_statements": fc.total_statements,
            "executed_branches": fc.executed_branches,
            "total_branches": fc.total_branches,
            "functions": funcs,
        }

    payload = {
        "total_statement_coverage": coverage.total_statement_coverage,
        "total_branch_coverage": coverage.total_branch_coverage,
        "files": files_ser,
        "timestamp": coverage.timestamp,
    }
    cache.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ── Critical path detection ───────────────────────────────────────────────────


def _build_fan_in_map(root: Path) -> dict[str, int]:
    """Build a map of file → fan-in (how many files import it) using import_graph."""
    try:
        from patchi.core.brain.import_graph import build_import_graph

        graph = build_import_graph(root)
        return {f: len(importers) for f, importers in graph.reverse.items()}
    except Exception as exc:
        _log.debug("import_graph build failed: %s", exc)
        return {}


def _detect_route_files(root: Path) -> set[str]:
    """Detect files that define routes (web routes/ directory, api routes, etc.)."""
    route_patterns = [
        "routes/*.py",
        "api/*.py",
        "web/routes/*.py",
        "web/api/*.py",
    ]
    route_files: set[str] = set()
    for pattern in route_patterns:
        for p in root.glob(pattern):
            rel = str(p.relative_to(root)).replace("\\", "/")
            route_files.add(rel)
    return route_files


# ── Main class ─────────────────────────────────────────────────────────────────


class CoveragePrioritizer:
    """Collects coverage data and prioritizes tests by impact."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def collect_coverage(self) -> CoverageData:
        """Collect coverage data from existing artifacts or fresh run.

        Priority order:
        1. Cached data (if .coverage/coverage.json unchanged)
        2. Existing coverage.json on disk
        3. Existing .coverage file (export via coverage json)
        4. Fresh pytest --cov run
        """
        # 1. Check cache
        cached = _load_cache(self.root)
        if cached is not None:
            _log.debug("Using cached coverage data")
            return cached

        # 2. Try existing coverage.json
        json_path = self.root / _COVERAGE_JSON
        if json_path.exists():
            data = _parse_coverage_json(json_path)
            if data is not None:
                _save_cache(self.root, data)
                return data

        # 3. Try .coverage file
        data = _read_raw_coverage(self.root / ".coverage")
        if data is not None:
            _save_cache(self.root, data)
            return data

        # 4. Fresh run
        _log.info("No existing coverage data — running pytest --cov")
        data = _run_pytest_cov(self.root)
        if data is not None:
            _save_cache(self.root, data)
            return data

        # 5. Graceful empty fallback
        _log.warning("Could not collect coverage data — returning empty")
        return CoverageData()

    def prioritize_tests(
        self,
        coverage: CoverageData,
        changed_files: list[str] | None = None,
    ) -> list[PrioritizedTest]:
        """Rank test files by impact priority.

        Scoring:
          +100  per changed source file this test covers
          +50   covers low-coverage areas (statement_coverage < 0.5)
          +30   covers critical path (high fan-in or route file)
          +10   baseline (any test file)
        """
        test_files = self._discover_test_files()
        if not test_files:
            return []

        changed_set = set(changed_files) if changed_files else set()
        fan_in = _build_fan_in_map(self.root)
        route_files = _detect_route_files(self.root)
        low_threshold = 0.5
        critical_fan_in = 3  # files imported by 3+ others are "critical"

        results: list[PrioritizedTest] = []
        for tf in test_files:
            score = 10.0  # baseline
            reasons: list[str] = []
            covers_changed = False
            covers_low = False
            covers_critical = False

            # Find source files this test covers by analyzing imports in the test
            covered_sources = self._infer_covered_sources(tf, coverage)

            for src in covered_sources:
                # Changed file bonus
                if src in changed_set:
                    score += 100.0
                    covers_changed = True
                    reasons.append(f"covers changed file {src}")

                # Low coverage bonus
                fc = coverage.files.get(src)
                if fc and fc.statement_coverage < low_threshold:
                    score += 50.0
                    covers_low = True
                    reasons.append(f"covers low-coverage {src} ({fc.statement_coverage:.0%})")

                # Critical path bonus
                fi = fan_in.get(src, 0)
                if fi >= critical_fan_in or src in route_files:
                    score += 30.0
                    covers_critical = True
                    kind = "route" if src in route_files else f"fan-in={fi}"
                    reasons.append(f"covers critical path {src} ({kind})")

            results.append(
                PrioritizedTest(
                    test_file=tf,
                    priority_score=score,
                    covers_changed_files=covers_changed,
                    covers_low_coverage=covers_low,
                    covers_critical_paths=covers_critical,
                    reasons=reasons,
                )
            )

        results.sort(key=lambda p: p.priority_score, reverse=True)
        return results

    def get_critical_uncovered(self, coverage: CoverageData) -> list[UncoveredPath]:
        """Identify functions on critical paths with 0% coverage.

        Critical = high fan-in from import_graph or in a routes/ directory.
        """
        fan_in = _build_fan_in_map(self.root)
        route_files = _detect_route_files(self.root)
        critical_fan_in = 3
        uncovered: list[UncoveredPath] = []

        for fpath, fc in coverage.files.items():
            is_critical = fan_in.get(fpath, 0) >= critical_fan_in or fpath in route_files
            if not is_critical:
                continue
            for fn in fc.functions:
                if not fn.executed:
                    uncovered.append(
                        UncoveredPath(
                            function_name=fn.name,
                            file=fpath,
                            line=fn.lineno,
                            fan_in=fan_in.get(fpath, 0),
                            in_routes=fpath in route_files,
                        )
                    )

        uncovered.sort(key=lambda u: (-u.fan_in, u.file))
        return uncovered

    # ── Private helpers ────────────────────────────────────────────────────────

    def _discover_test_files(self) -> list[str]:
        """Find all test_*.py files under the project (pruned walk)."""
        return sorted(iter_test_files(self.root))

    def _infer_covered_sources(
        self, test_file: str, coverage: CoverageData
    ) -> list[str]:
        """Infer which source files a test covers.

        Strategy (strongest signal first — Part 7 §0):
        1. AST import parsing (real dependency edge: test imports source).
        2. Name-based matching (test_foo.py likely tests foo.py) — LAST
           RESORT fallback only, never the sole signal for a critical verdict.

        COMPULSORY-REASON (Part 7 §4 KEEP-AND-HARDEN): without a coverage
        tool emitting per-test granularity, there is no structural proof of
        which source a test exercises. AST imports are the best available
        real signal; name-matching is kept only as a low-confidence
        corroborator for prioritization ordering (never for pass/fail).
        Measured via evals/cases + tests/test_coverage_prioritizer*.
        """
        covered: list[str] = []

        # Strategy 1 (primary): AST import parsing — real import edges.
        test_full = self.root / test_file
        try:
            content = test_full.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(content)
            except SyntaxError:
                tree = None
            if tree is not None:
                imported_mods: list[str] = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        imported_mods.extend(
                            (a.name or "").split(".")[0] for a in node.names
                        )
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported_mods.append(node.module.split(".")[0])
                        # from pkg.sub import x -> also record full dotted path
                        imported_mods.append(node.module)
                for mod in imported_mods:
                    if not mod:
                        continue
                    mod_path = mod.replace(".", "/")
                    for src_path in coverage.files:
                        src_no_ext = str(Path(src_path)).rsplit(".", 1)[0]
                        if src_no_ext.endswith(mod_path) or mod_path.endswith(
                            str(Path(src_path).stem)
                        ):
                            if src_path not in covered:
                                covered.append(src_path)
        except OSError:
            pass

        # Strategy 2 (fallback, low-confidence): name-based matching
        # (test_foo.py likely tests foo.py). Only fills gaps AST missed.
        test_stem = Path(test_file).stem  # test_foo
        base_name = test_stem.removeprefix("test_")
        for src_path in coverage.files:
            src_stem = Path(src_path).stem
            if src_stem == base_name and src_path not in covered:
                covered.append(src_path)

        return covered
