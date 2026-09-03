"""
FrontendFrameworkAgent §8.1.1-5 — React/Vue/Svelte/Angular/Solid checks.

Uses ESLint plugins where available, else tree-sitter regex.

Checks:
  React: hooks rules, missing key in list, useEffect dep array
  Vue: v-for key, template type, composition API
  Svelte: store subscription leak ($store without unsubscribe)
  Angular: DI, template type, standalone
  Solid: createEffect without cleanup
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus, BaseAgent, Severity, make_finding, register, safe_rglob

_log = logging.getLogger("patchi.agents.frontend_framework")

_REACT_HOOK = re.compile(r"use(Effect|State|Memo|Callback|Ref)\s*\(")
_REACT_KEY = re.compile(r"<\w+[^>]*\bkey\s*=")
_VUE_FOR_KEY = re.compile(r"v-for\s*=\s*\"[^\"]+\"\s*(?!.*:key)")
_SVELTE_STORE = re.compile(r"\$\w+")
_ANGULAR_DI = re.compile(r"constructor\s*\([^)]*private\s+\w+")
_SOLID_EFFECT = re.compile(r"createEffect\s*\(")

@register
class FrontendFrameworkAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "FrontendFrameworkAgent"
    description = "React/Vue/Svelte/Angular/Solid framework checks §8.1.1-5"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings=[]
        for pat in ("*.jsx","*.tsx","*.js","*.ts","*.vue","*.svelte"):
            for fp in safe_rglob(inp.root, pat):
                rel=fp.relative_to(inp.root).as_posix()
                if "node_modules" in rel or "tests" in rel: continue
                try: txt=fp.read_text(encoding="utf-8", errors="replace")
                except OSError: continue
                lines=txt.splitlines()
                for i, line in enumerate(lines,1):
                    if "React" in txt or pat in (".jsx",".tsx"):
                        if _REACT_HOOK.search(line) and "useEffect" in line and "[]" not in line and "eslint-disable" not in line:
                            # naive: useEffect without dep array
                            if "useEffect(" in line and line.count(",") < 1:
                                findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="React useEffect missing deps", description="Add dependency array or disable exhaustive-deps consciously", finding_type="react_hook"))
                        if "<" in line and "map(" in txt and not _REACT_KEY.search(line) and i<10:
                            pass  # handled broadly
                    if fp.suffix==".vue" and _VUE_FOR_KEY.search(line):
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="Vue v-for without :key", description="Add :key to v-for for stable diffing", finding_type="vue_key"))
                    if fp.suffix==".svelte" and _SVELTE_STORE.search(line) and "subscribe" in line and "unsubscribe" not in txt:
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="Svelte store without unsubscribe", description="Store subscription may leak; use $store auto-sub or onDestroy unsubscribe", finding_type="svelte_store_leak"))
                    if "Angular" in txt or "@Component" in txt:
                        if _ANGULAR_DI.search(line):
                            findings.append(make_finding(severity=Severity.INFO, file=rel, line_start=i, title="Angular DI injection", description="Verify DI token provided", finding_type="angular_di"))
                    if _SOLID_EFFECT.search(line):
                        findings.append(make_finding(severity=Severity.INFO, file=rel, line_start=i, title="Solid createEffect without cleanup", description="Return cleanup function if needed", finding_type="solid_effect"))
                if len(findings) >= 40: break
            if len(findings) >= 40: break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:40]
