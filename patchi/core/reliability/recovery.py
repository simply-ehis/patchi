"""RecoveryAnalyzer — analyze data flows for recovery patterns.

Checks that critical data paths have circuit breakers, retry logic,
and graceful degradation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from patchi.core.assurance.graph import AssuranceGraph

_log = logging.getLogger("patchi.reliability.recovery")


@dataclass
class RecoveryGap:
    """A data flow missing a recovery pattern."""

    file: str
    flow: str  # "source → sink"
    missing_pattern: str  # "circuit_breaker", "retry", "fallback", "timeout"
    severity: str
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "flow": self.flow,
            "missing_pattern": self.missing_pattern,
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


class RecoveryAnalyzer:
    """Analyze data flows for missing recovery patterns."""

    def __init__(self, root: Path, graph: AssuranceGraph | None = None):
        self._root = root
        self._graph = graph

    def analyze(self, max_gaps: int = 30) -> list[RecoveryGap]:
        """Analyze the project for missing recovery patterns."""
        gaps: list[RecoveryGap] = []

        # Check data flows from the graph
        if self._graph:
            gaps.extend(self._graph_flow_analysis())

        # Check common patterns in code
        gaps.extend(self._code_pattern_analysis())

        return gaps[:max_gaps]

    def _graph_flow_analysis(self) -> list[RecoveryGap]:
        """Analyze data flows from the assurance graph for recovery gaps."""
        gaps: list[RecoveryGap] = []

        for claim in self._graph.claims.values():
            for ev in claim.evidence:
                if not ev.supports:
                    continue
                artifact = ev.artifact
                source = artifact.get("source", "")
                sink = artifact.get("sink", "")

                if not source or not sink:
                    continue

                # External sinks need circuit breakers
                if any(kw in sink.lower() for kw in ["api", "http", "network", "remote"]):
                    gaps.append(
                        RecoveryGap(
                            file=source,
                            flow=f"{source} → {sink}",
                            missing_pattern="circuit_breaker",
                            severity="high",
                            recommendation=f"Add circuit breaker between {source} and external {sink}",
                        )
                    )

                # Database sinks need retry with backoff
                if any(kw in sink.lower() for kw in ["db", "database", "sql", "redis"]):
                    gaps.append(
                        RecoveryGap(
                            file=source,
                            flow=f"{source} → {sink}",
                            missing_pattern="retry",
                            severity="medium",
                            recommendation=f"Add retry with exponential backoff for {sink} operations",
                        )
                    )

        return gaps

    def _code_pattern_analysis(self) -> list[RecoveryGap]:
        """Scan code for missing recovery patterns."""
        gaps: list[RecoveryGap] = []

        for py_file in sorted(self._root.rglob("*.py")):
            if ".patchi" in str(py_file) or "__pycache__" in str(py_file):
                continue
            if ".venv" in str(py_file):
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            rel = (
                str(py_file.relative_to(self._root))
                if self._root in py_file.parents
                else str(py_file)
            )

            # Check for network calls without retry
            if re.search(r"requests\.(get|post|put|delete)\(", content):
                if "retry" not in content.lower() and "tenacity" not in content.lower():
                    gaps.append(
                        RecoveryGap(
                            file=rel,
                            flow="HTTP request",
                            missing_pattern="retry",
                            severity="medium",
                            recommendation="Add retry with backoff for HTTP requests",
                        )
                    )

            # Check for DB operations without rollback
            if re.search(r"\.execute\(|\.commit\(", content):
                if "rollback" not in content.lower():
                    gaps.append(
                        RecoveryGap(
                            file=rel,
                            flow="Database operation",
                            missing_pattern="rollback",
                            severity="high",
                            recommendation="Add try/except with rollback for database operations",
                        )
                    )

        return gaps
