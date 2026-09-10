"""CoveragePrioritizerAgent — ranks uncovered code by git churn frequency.

Covers §6.1.1:
- Parse coverage reports (.coverage, lcov, cobertura)
- Cross-ref with git blame frequency per file
- Highlight \"hot\" files (high churn) with low coverage as priority targets
"""

from __future__ import annotations

import logging
import subprocess
from collections import defaultdict
from pathlib import Path

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

_log = logging.getLogger("patchi.agents.coverage_prioritizer")


def _get_git_churn(root: Path, max_files: int = 100) -> dict[str, int]:
    """Get commit count per file via git log."""
    churn: dict[str, int] = defaultdict(int)
    try:
        result = subprocess.run(
            ["git", "log", "--name-only", "--pretty=format:", "-1000"],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and Path(line).suffix in (
                ".py",
                ".js",
                ".ts",
                ".rs",
                ".go",
                ".java",
                ".c",
                ".cpp",
                ".swift",
                ".rb",
                ".svelte",
                ".jsx",
                ".tsx",
            ):
                churn[line] += 1
    except Exception as e:
        _log.debug("_get_git_churn failed: %s", e)
    return dict(sorted(churn.items(), key=lambda x: -x[1])[:max_files])


def _parse_lcov(root: Path) -> set[str]:
    """Parse lcov coverage files — extract files with <80% coverage."""
    low_coverage: set[str] = set()
    for lcov_file in safe_rglob(root, "*.info"):
        try:
            content = lcov_file.read_text(encoding="utf-8")
        except Exception as e:
            _log.debug("_parse_lcov failed: %s", e)
            continue
        current_file = ""
        total_lines = 0
        covered_lines = 0
        for line in content.splitlines():
            if line.startswith("SF:"):
                current_file = line[3:]
            elif line.startswith("DA:"):
                total_lines += 1
                _, hits = line.split(",", 1)
                if int(hits) > 0:
                    covered_lines += 1
            elif line.startswith("end_of_record"):
                if total_lines > 0:
                    pct = covered_lines / total_lines * 100
                    if pct < 80:
                        try:
                            rel = Path(current_file).relative_to(root).as_posix()
                            low_coverage.add(rel)
                        except ValueError:
                            low_coverage.add(current_file)
                current_file = ""
                total_lines = 0
                covered_lines = 0
    return low_coverage


def _parse_coverage_json(root: Path) -> set[str]:
    """Parse .coverage or coverage.json files."""
    low_coverage: set[str] = set()
    for cov_file in safe_rglob(root, ".coverage"):
        if cov_file.is_file():
            continue
    for cov_file in safe_rglob(root, "coverage.json"):
        try:
            import json

            data = json.loads(cov_file.read_text(encoding="utf-8"))
            for file_path, info in data.items():
                if isinstance(info, dict):
                    total = (
                        info.get("lines", {}).get("total", 0)
                        or info.get("totals", {}).get("lines", {}).get("count", 0)
                        or 0
                    )
                    covered = (
                        info.get("lines", {}).get("covered", 0)
                        or info.get("totals", {}).get("lines", {}).get("covered", 0)
                        or 0
                    )
                    if total > 0 and (covered / total * 100) < 80:
                        low_coverage.add(file_path)
        except Exception as e:
            _log.debug("_parse_coverage_json failed: %s", e)
    return low_coverage


@register
class CoveragePrioritizerAgent(BaseAgent):
    """Ranks uncovered code by git churn frequency — hot files missing tests."""

    group = AgentGroup.SCANNER
    name = "CoveragePrioritizerAgent"
    description = "Cross-ref git blame frequency with coverage to find hot untested files"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        churn = _get_git_churn(inp.root)
        low_coverage = _parse_lcov(inp.root) | _parse_coverage_json(inp.root)

        hot_untested: list[dict] = []
        for file_path, commits in churn.items():
            if file_path in low_coverage:
                hot_untested.append({"file": file_path, "commits": commits})

        hot_untested.sort(key=lambda x: -x["commits"])

        result.data["churn_data"] = churn
        result.data["low_coverage_files"] = list(low_coverage)
        result.data["hot_untested"] = hot_untested
        result.data["total_low_coverage"] = len(low_coverage)
        result.data["total_hot_untested"] = len(hot_untested)
        result.files_scanned = len(churn)

        for item in hot_untested:
            result.findings.append(
                make_finding(
                    self.name,
                    "hot_untested",
                    Severity.MEDIUM,
                    item["file"],
                    f"Hot file with low coverage: {item['file']} ({item['commits']} commits)",
                    detail=f"Modified {item['commits']} times in recent history but coverage <80%",
                    suggestion="Prioritize writing tests for this frequently-changed file",
                )
            )

        if not low_coverage and not churn:
            result.findings.append(
                make_finding(
                    self.name,
                    "no_coverage_data",
                    Severity.INFO,
                    "",
                    "No coverage data or git history found",
                )
            )

        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
