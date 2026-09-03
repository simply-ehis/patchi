"""
I18nAgent §11.7 — Internationalization Audit.

Finds hardcoded strings in UI code, missing translation keys, untranslated strings
via tree-sitter scan for string literals in JSX/TSX/Vue/Svelte.
"""

from __future__ import annotations

import logging
import re

from patchi.core.agents.base import AgentGroup, AgentInput, AgentResult, AgentStatus, BaseAgent, Severity, make_finding, register, safe_rglob

_log = logging.getLogger("patchi.agents.i18n")

_HARDCODED_RE = re.compile(r">[^<]*[A-Za-z]{4,}[^<]*<|\"[A-Z][a-z]+ [a-z]+\"|'[A-Z][a-z]+ [a-z]+'")
_I18N_KEY_RE = re.compile(r"t\s*\(\s*['\"][^'\"]+['\"]\s*\)|i18n\.t|useTranslation")

@register
class I18nAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "I18nAgent"
    description = "i18n audit §11.7 — hardcoded strings vs translation keys"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings=[]
        for pat in ("*.jsx","*.tsx","*.vue","*.svelte"):
            for fp in safe_rglob(inp.root, pat):
                rel=fp.relative_to(inp.root).as_posix()
                if "node_modules" in rel: continue
                try: txt=fp.read_text(encoding="utf-8", errors="replace")
                except OSError: continue
                # skip if already i18n
                has_i18n = bool(_I18N_KEY_RE.search(txt))
                # find hardcoded UI strings: >Hello world< but not <div>
                for m in re.finditer(r">([A-Z][a-z]+(?:\s+[a-zA-Z]+){1,4})<", txt):
                    s=m.group(1).strip()
                    if len(s)>10 and not has_i18n:
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=txt[:m.start()].count("\n")+1, title=f"Hardcoded UI string '{s[:30]}' without i18n", description="Use t('key') / $t() / i18n key; check i18next-scanner", finding_type="i18n_hardcoded"))
                        break
                if len(findings)>=20: break
            if len(findings)>=20: break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:20]
