"""Documentation gap detector — flags expected docs that are missing, partial, or stale.

Compares what a project *has* (directories, test files, security findings,
existing docs) against what the knowledge-doc generator would produce, and
reports discrepancies as ``DocGap`` objects.

Usage::

    from patchi.core.brain.doc_gaps import detect_doc_gaps

    gaps = detect_doc_gaps(project_root, scan_result)
    for gap in gaps:
        print(f"[{gap.status}] {gap.area}: {gap.suggestion}")
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_DOC_STALE_THRESHOLD_DAYS = 7


@dataclass
class DocGap:
    """A documentation area that should exist but doesn't, or is incomplete."""

    area: str
    expected_doc: str
    status: str  # "missing" | "partial" | "stale"
    suggestion: str


def _has_directory(root: Path, *names: str) -> bool:
    """Return True if any of *names* exist as a directory under *root*."""
    for name in names:
        if (root / name).is_dir():
            return True
    return False


def _has_test_files(file_infos: list[dict]) -> bool:
    """Return True if the scan data includes at least one test file."""
    test_dir_names = {"tests", "test", "__tests__", "spec", "specs", "testing"}
    for fi in file_infos:
        path = (fi.get("path", "") if isinstance(fi, dict) else getattr(fi, "path", "")).replace("\\", "/")
        parts = path.split("/")
        if any(p.lower() in test_dir_names for p in parts):
            return True
        stem = path.rsplit("/", 1)[-1] if "/" in path else path
        if stem.startswith("test_") or stem.endswith("_test") or ".test." in stem or ".spec." in stem:
            return True
    return False


def _has_security_findings(scan_result: dict) -> bool:
    """Return True if the scan result contains any security findings."""
    findings = scan_result.get("security_findings")
    if findings and isinstance(findings, list) and len(findings) > 0:
        return True
    scan_results = scan_result.get("scan_results", {})
    if scan_results and isinstance(scan_results, dict):
        for agent_data in scan_results.values():
            if isinstance(agent_data, dict) and agent_data.get("findings"):
                return True
    return False


def _doc_exists_and_recent(docs_dir: Path, filename: str, max_age_days: int) -> tuple[bool, bool]:
    """Return (exists, is_recent).

    ``is_recent`` is True when the file exists and was modified fewer than
    *max_age_days* ago.
    """
    doc_path = docs_dir / filename
    if not doc_path.exists():
        return False, False
    try:
        mtime = doc_path.stat().st_mtime
    except OSError:
        return True, False
    age_days = (time.time() - mtime) / 86400
    return True, age_days <= max_age_days


def detect_doc_gaps(
    project_root: Path,
    scan_result: dict[str, Any],
) -> list[DocGap]:
    """Detect documentation gaps for *project_root* based on scan data.

    Parameters
    ----------
    project_root:
        Absolute path to the project root.
    scan_result:
        Dict produced by ``Brain.scan()`` (summary_dict) or equivalent.
        Expected keys (all optional — missing keys produce empty checks):
          - ``file_infos``: list of FileInfo or dicts
          - ``security_findings``: list of Finding dicts
          - ``scan_results``: dict of agent_name → result_dict

    Returns
    -------
    list[DocGap]
        Gaps found, ordered by severity (missing > partial > stale).
    """
    docs_dir = project_root / "docs"
    file_infos = _normalise_file_infos(scan_result.get("file_infos", []))
    gaps: list[DocGap] = []

    # 1. API Surface — flag if routes/api dirs exist but doc is missing.
    has_route_dirs = _has_directory(project_root, "routes", "api", "endpoints", "controllers")
    has_routes_in_scan = bool(scan_result.get("routes"))
    if has_route_dirs or has_routes_in_scan:
        exists, _ = _doc_exists_and_recent(docs_dir, "API_SURFACE.md", max_age_days=99999)
        if not exists:
            gaps.append(DocGap(
                area="API surface",
                expected_doc="docs/API_SURFACE.md",
                status="missing",
                suggestion="Project has route directories but no API_SURFACE.md — run `p docs` to generate.",
            ))

    # 2. Test Coverage — flag if test files exist but doc is missing.
    if _has_test_files(file_infos):
        exists, _ = _doc_exists_and_recent(docs_dir, "TEST_COVERAGE.md", max_age_days=99999)
        if not exists:
            gaps.append(DocGap(
                area="Test coverage",
                expected_doc="docs/TEST_COVERAGE.md",
                status="missing",
                suggestion="Project has test files but no TEST_COVERAGE.md — run `p docs` to generate.",
            ))

    # 3. Security Domains — flag if security findings exist but doc is missing.
    if _has_security_findings(scan_result):
        exists, _ = _doc_exists_and_recent(docs_dir, "SECURITY_DOMAINS.md", max_age_days=99999)
        if not exists:
            gaps.append(DocGap(
                area="Security domains",
                expected_doc="docs/SECURITY_DOMAINS.md",
                status="missing",
                suggestion="Project has security findings but no SECURITY_DOMAINS.md — run `p docs` to generate.",
            ))

    # 4. Architecture staleness — flag if ARCHITECTURE.md is older than threshold.
    arch_exists, arch_recent = _doc_exists_and_recent(
        docs_dir, "ARCHITECTURE.md", _DOC_STALE_THRESHOLD_DAYS,
    )
    if arch_exists and not arch_recent:
        gaps.append(DocGap(
            area="Architecture",
            expected_doc="docs/ARCHITECTURE.md",
            status="stale",
            suggestion=(
                f"ARCHITECTURE.md is older than {_DOC_STALE_THRESHOLD_DAYS} days — "
                "run `p docs --regen` to refresh."
            ),
        ))

    # 5. Partial detection — doc exists but is suspiciously small (< 5 meaningful lines).
    for doc_name, area_label in [
        ("API_SURFACE.md", "API surface"),
        ("TEST_COVERAGE.md", "Test coverage"),
        ("SECURITY_DOMAINS.md", "Security domains"),
    ]:
        doc_path = docs_dir / doc_name
        if doc_path.exists():
            try:
                text = doc_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            meaningful = [
                ln
                for ln in text.splitlines()
                if ln.strip() and not ln.strip().startswith(("<!--", "#"))
            ]
            if len(meaningful) < 5:
                gaps.append(DocGap(
                    area=area_label,
                    expected_doc=f"docs/{doc_name}",
                    status="partial",
                    suggestion=f"{doc_name} exists but has very little content — may need regeneration.",
                ))

    # Sort: missing first, then partial, then stale.
    order = {"missing": 0, "partial": 1, "stale": 2}
    gaps.sort(key=lambda g: (order.get(g.status, 9), g.area))
    return gaps


def _normalise_file_infos(raw: list) -> list[dict]:
    """Convert list of FileInfo objects/dicts to plain dicts."""
    if not raw:
        return []
    if raw and isinstance(raw[0], dict):
        return raw
    return [fi.to_dict() if hasattr(fi, "to_dict") else vars(fi) for fi in raw]
