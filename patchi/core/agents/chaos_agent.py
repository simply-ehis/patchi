"""
ChaosAgent §5.3.3-4 — Race Condition + Chaos Testing.

Race: concurrent duplicate requests to same endpoint → duplicate records.
Chaos: missing retry/backoff on network, no circuit breaker.
"""

from __future__ import annotations

import logging
import re

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus, BaseAgent, Severity, make_finding, register, safe_rglob

_log = logging.getLogger("patchi.agents.chaos")

_RACE_SENSITIVE = re.compile(r"(create|insert|update|upsert|transaction)", re.I)
_NO_RETRY = re.compile(r"fetch\s*\(|axios\.|httpx\.|requests\.")
_HAS_RETRY = re.compile(r"retry|backoff|circuit|breaker|tenacity|resilience")

@register
class ChaosAgent(BaseAgent):
    group = AgentGroup.TEST
    name = "ChaosAgent"
    description = "Race duplicate requests + Chaos missing retry/backoff §5.3.3-4"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings=[]
        for pat in ("*.py","*.js","*.ts"):
            for fp in safe_rglob(inp.root, pat):
                rel=fp.relative_to(inp.root).as_posix()
                if "tests" in rel or "node_modules" in rel: continue
                try: txt=fp.read_text(encoding="utf-8", errors="replace")
                except OSError: continue
                # Race: file write without lock/atomic
                if "open(" in txt and "lock" not in txt.lower() and "atomic" not in txt.lower():
                    if _RACE_SENSITIVE.search(txt) and "with open" in txt:
                        findings.append(make_finding(severity=Severity.MEDIUM, file=rel, line_start=txt[:txt.index("open(")].count("\n")+1, title="Possible race — file write without lock", description="Concurrent requests may duplicate records; use atomic write or DB transaction", finding_type="race_file_write"))
                # Chaos: fetch without retry
                if _NO_RETRY.search(txt) and not _HAS_RETRY.search(txt):
                    # only flag if multiple fetches
                    if txt.count("fetch(") + txt.count("axios.") > 2:
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=0, title="No retry/backoff on network calls", description="Add retry with backoff + circuit breaker for chaos resilience", finding_type="chaos_no_retry"))
                        break
                if len(findings) >= 20: break
            if len(findings) >= 20: break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:20]
