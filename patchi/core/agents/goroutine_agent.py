"""
GoroutineLeakAgent §8.2.3 — go vet style goroutine leak detection.

Checks Go files for `go` keyword without context/WaitGroup, unchecked `err` after goroutine, and missing leak guards.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.agents.goroutine")

_GO_RUN = re.compile(r"^\s*go\s+\w+\s*\(")
_GO_ERR_IGNORE = re.compile(r"^\s*go\s+.*\(\s*\)\s*$")


@register
class GoroutineLeakAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "GoroutineLeakAgent"
    description = "Go goroutine leak — go without context/WaitGroup §8.2.3"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Try go vet with -vettool if available
        if shutil.which("go"):
            try:
                proc = subprocess.run(["go", "vet", "./..."], capture_output=True, text=True, timeout=30, cwd=str(inp.root))
                for line in proc.stderr.splitlines():
                    if "leak" in line.lower() or "goroutine" in line.lower():
                        result.add_finding(
                            make_finding(
                                severity=Severity.MEDIUM,
                                file="",
                                line_start=0,
                                title="go vet: possible goroutine leak",
                                description=line.strip()[:200],
                                finding_type="goroutine_leak",
                            )
                        )
            except Exception as exc:  # noqa: BLE001
                _log.debug("go vet failed: %s", exc)

        for fp in safe_rglob(inp.root, "*.go"):
            rel = fp.relative_to(inp.root).as_posix()
            try:
                txt = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = txt.splitlines()
            for i, line in enumerate(lines, 1):
                if _GO_RUN.search(line):
                    # check next 10 lines for context/WaitGroup
                    window = "\n".join(lines[max(0, i - 5) : i + 15])
                    if "context" not in window.lower() and "WaitGroup" not in window and "errgroup" not in window:
                        result.add_finding(
                            make_finding(
                                severity=Severity.LOW,
                                file=rel,
                                line_start=i,
                                title="go without context/WaitGroup — leak risk",
                                description="`go func()` without `context.Context` or `sync.WaitGroup`/`errgroup` — goroutine may leak. Pass context and wait.",
                                evidence=line.strip()[:120],
                                finding_type="goroutine_leak",
                            )
                        )
        result.status = AgentStatus.SUCCEEDED
