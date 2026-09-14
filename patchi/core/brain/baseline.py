"""
Baseline locking for Patchi.

Snapshots the current finding state and compares against previous baselines.
Enables "only fail on new issues" workflow for CI/CD.

Baseline is stored in `.patchi/memory/baseline.json`.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from patchi.core.agents.base import Finding, Severity

_log = logging.getLogger("patchi.brain.baseline")


@dataclass
class BaselineSnapshot:
    """A snapshot of findings at a point in time."""

    created_at: str = ""
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_agent: dict[str, int] = field(default_factory=dict)
    finding_hashes: set[str] = field(default_factory=set)
    file_finding_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "created_at": self.created_at,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "by_agent": self.by_agent,
            "finding_hashes": sorted(self.finding_hashes),
            "file_finding_counts": self.file_finding_counts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> BaselineSnapshot:
        return cls(
            created_at=data.get("created_at", ""),
            total_findings=data.get("total_findings", 0),
            by_severity=data.get("by_severity", {}),
            by_agent=data.get("by_agent", {}),
            finding_hashes=set(data.get("finding_hashes", [])),
            file_finding_counts=data.get("file_finding_counts", {}),
        )


@dataclass
class BaselineDiff:
    """Difference between current scan and baseline."""

    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[dict] = field(default_factory=list)
    total_baseline: int = 0
    total_current: int = 0
    new_count: int = 0
    resolved_count: int = 0
    has_regression: bool = False
    summary: str = ""


def _finding_hash(finding: Finding) -> str:
    """Deterministic hash for a finding — used to detect new vs known issues."""
    raw = f"{finding.file}:{finding.line}:{finding.type}:{finding.severity.value}:{finding.message}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _finding_dict_hash(finding: dict) -> str:
    raw = (
        f"{finding.get('file', '')}:{finding.get('line', 0)}:{finding.get('type', '')}"
        f":{finding.get('severity', '')}:{finding.get('message', '')}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _baseline_path(root: Path) -> Path:
    return root / ".patchi" / "memory" / "baseline.json"


def save_baseline(findings: list[Finding], root: Path) -> BaselineSnapshot:
    """Snapshot current findings as the new baseline."""
    snapshot = BaselineSnapshot(
        created_at=datetime.now(UTC).isoformat(),
        total_findings=len(findings),
        by_severity={s.value: 0 for s in Severity},
        by_agent={},
        finding_hashes=set(),
        file_finding_counts={},
    )

    for f in findings:
        snapshot.by_severity[f.severity.value] = snapshot.by_severity.get(f.severity.value, 0) + 1
        snapshot.by_agent[f.agent] = snapshot.by_agent.get(f.agent, 0) + 1
        snapshot.finding_hashes.add(_finding_hash(f))
        snapshot.file_finding_counts[f.file] = snapshot.file_finding_counts.get(f.file, 0) + 1

    path = _baseline_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
    return snapshot


def load_baseline(root: Path) -> BaselineSnapshot | None:
    """Load the saved baseline, if any."""
    path = _baseline_path(root)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return BaselineSnapshot.from_dict(data)
    except Exception as e:
        _log.warning("load_baseline failed: %s", e)
        return None


def diff_baseline(current_findings: list[dict | Finding], root: Path) -> BaselineDiff | None:
    """
    Compare current findings against baseline.
    Returns None if no baseline exists.

    Accepts both Finding objects and dicts (from JSON output).
    """
    baseline = load_baseline(root)
    if baseline is None:
        return None

    # Convert all to Finding objects for uniform handling
    normalized: list[Finding] = []
    for item in current_findings:
        if isinstance(item, Finding):
            normalized.append(item)
        elif isinstance(item, dict):
            normalized.append(
                Finding(
                    agent=item.get("agent", ""),
                    type=item.get("type", item.get("finding_type", "")),
                    severity=Severity(item.get("severity", "info")),
                    file=item.get("file", ""),
                    line=item.get("line", 0),
                    message=item.get("message", ""),
                )
            )

    current_hashes = {_finding_hash(f) for f in normalized}

    new_findings = [f for f in normalized if _finding_hash(f) not in baseline.finding_hashes]
    resolved_hashes = baseline.finding_hashes - current_hashes

    diff = BaselineDiff(
        new_findings=new_findings,
        resolved_findings=[{"hash": h} for h in resolved_hashes],
        total_baseline=baseline.total_findings,
        total_current=len(normalized),
        new_count=len(new_findings),
        resolved_count=len(resolved_hashes),
        has_regression=len(new_findings) > 0,
    )

    # Build summary
    parts = []
    if diff.new_count > 0:
        parts.append(f"{diff.new_count} new finding(s)")
    if diff.resolved_count > 0:
        parts.append(f"{diff.resolved_count} resolved")
    parts.append(f"baseline: {diff.total_baseline}")
    parts.append(f"current: {diff.total_current}")
    diff.summary = ", ".join(parts)

    return diff


def update_baseline(findings: list[Finding | dict], root: Path) -> BaselineSnapshot:
    """Convenience: load current findings, diff against baseline, save new baseline."""
    normalized: list[Finding] = []
    for item in findings:
        if isinstance(item, Finding):
            normalized.append(item)
        elif isinstance(item, dict):
            normalized.append(
                Finding(
                    agent=item.get("agent", ""),
                    type=item.get("type", item.get("finding_type", "")),
                    severity=Severity(item.get("severity", "info")),
                    file=item.get("file", ""),
                    line=item.get("line", 0),
                    message=item.get("message", ""),
                )
            )
    return save_baseline(normalized, root)
