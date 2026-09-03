"""
ModernizationAgent §7.1.4 — var→const/let, .then→async/await, require→import codemods.

Wraps jscodeshift / ts-migrate style via regex + tree-sitter where possible.
Emits Findings of type modernization_* with suggestion to run codemod.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus, BaseAgent, Severity, make_finding, register, safe_rglob

_log = logging.getLogger("patchi.agents.modernization")

_VAR_RE = re.compile(r"^\s*var\s+\w+")
_THEN_RE = re.compile(r"\.then\s*\(")
_REQUIRE_RE = re.compile(r"require\s*\(\s*['\"][^'\"]+['\"]\s*\)")
_CLASS_RE = re.compile(r"class\s+\w+\s+extends\s+React\.Component")

@register
class ModernizationAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "ModernizationAgent"
    description = "Codemods §7.1.4 var→const, then→await, require→import"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings=[]
        for pat in ("*.js","*.jsx","*.ts","*.tsx"):
            for fp in safe_rglob(inp.root, pat):
                rel=fp.relative_to(inp.root).as_posix()
                if "node_modules" in rel: continue
                try: txt=fp.read_text(encoding="utf-8", errors="replace")
                except OSError: continue
                lines=txt.splitlines()
                for i, line in enumerate(lines,1):
                    if _VAR_RE.search(line):
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="var → const/let", description="jscodeshift var-to-const: replace var with const/let", finding_type="modernization_var"))
                    if _THEN_RE.search(line):
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title=".then() → async/await", description="Codemod .then() chain to async/await for readability", finding_type="modernization_then"))
                    if _REQUIRE_RE.search(line):
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="require() → import", description="Migrate to ESM import via jscodeshift", finding_type="modernization_require"))
                    if _CLASS_RE.search(line):
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="Class component → functional", description="Codemod React class to functional + hooks", finding_type="modernization_class"))
                    if len(findings) >= 40: break
                if len(findings) >= 40: break
            if len(findings) >= 40: break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:40]
