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

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    get_shard_files,
    make_finding,
    register,
    safe_rglob,
)
from patchi.core.brain.code_query import (
    js_new_without_catch,
    lang_for_file,
    parse_js,
)

_log = logging.getLogger("patchi.agents.promise_rejection")


@register
class PromiseRejectionTrackerAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "PromiseRejectionTrackerAgent"
    description = "Unhandled promise rejections / missing catch — §5.1.1"
    timeout = 60
    shardable = True
    supported_languages = ["JavaScript", "TypeScript"]

    _MAX_FILES = 500

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        files_scanned = 0
        # Check for missing global handlers in entry points
        entry_has_handler = False
        for pattern in ("*.js", "*.ts", "*.tsx"):
            for fp in get_shard_files(inp, pattern):
                if files_scanned >= self._MAX_FILES:
                    break
                if fp.name in ("app.js", "server.js", "index.js", "main.js") or "entry" in fp.name.lower():
                    try:
                        txt = fp.read_text(encoding="utf-8", errors="replace")
                        if "unhandledRejection" in txt or "uncaughtException" in txt:
                            entry_has_handler = True
                    except OSError:
                        continue
                files_scanned += 1

        for pattern in ("*.js", "*.ts", "*.tsx", "*.jsx"):
            for fp in get_shard_files(inp, pattern):
                if files_scanned >= self._MAX_FILES:
                    break
                rel = fp.relative_to(inp.root).as_posix()
                if "tests" in rel or "node_modules" in rel:
                    continue
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                lang = lang_for_file(rel)
                tree = parse_js(txt, lang)
                if tree is None:
                    continue
                for line in js_new_without_catch(tree, ("Promise",), lang):
                    findings.append(
                        make_finding(
                            severity=Severity.LOW,
                            file=rel,
                            line_start=line,
                            title="Promise without catch — unhandledRejection risk",
                            description="`new Promise` without `.catch` or `await try/catch` — aggregate via process.on('unhandledRejection') during test runs (see §5.1.1).",
                            finding_type="promise_no_catch",
                        )
                    )
                    if len(findings) >= 30:
                        break
                if len(findings) >= 30:
                    break
                files_scanned += 1
            if files_scanned >= self._MAX_FILES:
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
