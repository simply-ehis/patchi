"""
PromiseRejectionTracker §5.1.1 — unhandledRejection / uncaughtException during test runs.

Agents report via this scanner; runtime instrumentation is in test agents:
  - Node: process.on('unhandledRejection') aggregator
  - Python: sys.excepthook for unhandled

This agent scans for *missing* handlers — code that creates promises/tasks
without catch, and test runs that never register handlers.
"""

from __future__ import annotations

import logging
import re

from patchi.core.agents.base import (
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

_log = logging.getLogger("patchi.agents.promise_rejection")


# JS/TS: new Promise, .then without .catch, async without try/catch
_PROMISE_NO_CATCH = re.compile(r"\bnew\s+Promise\s*\(")
_THEN_NO_CATCH = re.compile(r"\.then\s*\([^)]*\)\s*(?:\.then[^)]*\)\s*)*\s*;")
_ASYNC_NO_TRY = re.compile(r"async\s+function\s+\w*\s*\([^)]*\)\s*\{[^}]*\bawait\b", re.DOTALL)


@register
class PromiseRejectionTrackerAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "PromiseRejectionTrackerAgent"
    description = "Unhandled promise rejections / missing catch — §5.1.1"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        # Check for missing global handlers in entry points
        entry_has_handler = False
        for pattern in ("*.js", "*.ts", "*.tsx"):
            for fp in safe_rglob(inp.root, pattern):
                if fp.name in ("app.js", "server.js", "index.js", "main.js") or "entry" in fp.name.lower():
                    try:
                        txt = fp.read_text(encoding="utf-8", errors="replace")
                        if "unhandledRejection" in txt or "uncaughtException" in txt:
                            entry_has_handler = True
                    except OSError:
                        continue

        for pattern in ("*.js", "*.ts", "*.tsx", "*.jsx"):
            for fp in safe_rglob(inp.root, pattern):
                rel = fp.relative_to(inp.root).as_posix()
                if "tests" in rel or "node_modules" in rel:
                    continue
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                lines = txt.splitlines()
                for i, line in enumerate(lines, 1):
                    if _PROMISE_NO_CATCH.search(line) and ".catch" not in "\n".join(lines[i : i + 5]):
                        findings.append(
                            make_finding(
                                severity=Severity.LOW,
                                file=rel,
                                line_start=i,
                                title="Promise without catch — unhandledRejection risk",
                                description="`new Promise` without `.catch` or `await try/catch` — aggregate via process.on('unhandledRejection') during test runs (see §5.1.1).",
                                evidence=line.strip()[:120],
                                finding_type="promise_no_catch",
                            )
                        )
                        if len(findings) >= 30:
                            break
            if len(findings) >= 30:
                break

        if not entry_has_handler:
            findings.append(
                make_finding(
                    severity=Severity.INFO,
                    file="",
                    line_start=0,
                    title="No global unhandledRejection handler detected",
                    description="No `process.on('unhandledRejection')` in entry points — add aggregator to catch unhandled promises during CI (Node) / sys.excepthook (Python).",
                    finding_type="missing_unhandled_handler",
                )
            )

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings[:30]
        result.data["missing_handler"] = not entry_has_handler
