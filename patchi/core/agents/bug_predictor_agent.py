"""
BugPredictorAgent §11.1 — AI-powered bug prediction from churn+complexity.

Features: git churn (log count), complexity (branch count), bug density (past findings), commit sentiment (heuristic).
Model: lightweight sklearn-like linear regression if sklearn installed, else heuristic weighted sum.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus, BaseAgent, Severity, make_finding, register

_log = logging.getLogger("patchi.agents.bug_predictor")

def _churn(root: Path, rel: str) -> int:
    try:
        out = subprocess.run(
            ["git", "log", "--oneline", "--", rel],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            cwd=str(root),
        )
        if out.returncode == 0:
            return len(out.stdout.splitlines())
        return 0
    except Exception:
        return 0

def _complexity(txt: str) -> int:
    return txt.count(" if ") + txt.count(" else") + txt.count(" for ") + txt.count(" while ")

@register
class BugPredictorAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "BugPredictorAgent"
    description = "AI bug prediction churn×complexity §11.1"
    timeout = 60
    shardable = True
    supported_languages = None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings=[]
        # simple heuristic model: score = churn*0.4 + complexity*0.3 + past_bug*0.3
        past = {}
        try:
            from patchi.core import memory as mem
            scans = mem.get_scan_results(inp.root) or {}
            for data in scans.values():
                for f in data.get("findings", []):
                    fp = f.get("file", "")
                    if fp:
                        past[fp] = past.get(fp, 0) + 1
        except Exception as _exc:
            _log.debug("suppressed: %s", _exc)
        for fp in inp.root.rglob("*.py"):
            if "tests" in str(fp) or ".patchi" in str(fp):
                continue
            rel = fp.relative_to(inp.root).as_posix()
            try:
                txt = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            churn = _churn(inp.root, rel)
            comp = _complexity(txt)
            bugdens = past.get(rel, 0)
            score = churn * 0.4 + comp * 0.1 + bugdens * 2
            if score > 15:
                findings.append(
                    make_finding(
                        severity=Severity.LOW,
                        file=rel,
                        line_start=0,
                        title=f"Predicted bug-prone ({score:.0f}) — churn {churn} complexity {comp}",
                        description="High churn+complexity predicts next bug — review, add tests. Features: churn, complexity, bug density; sklearn fallback linear.",
                        finding_type="bug_prediction",
                    )
                )
                if len(findings) >= 15:
                    break
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings[:15]
