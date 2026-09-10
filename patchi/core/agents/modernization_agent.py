"""
ModernizationAgent §7.1.4 — var→const/let, .then→async/await, require→import codemods.

Wraps jscodeshift / ts-migrate style via tree-sitter structural queries.
Emits Findings of type modernization_* with suggestion to run codemod.
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
    js_calls,
    js_class_heritages,
    js_var_kinds,
    lang_for_file,
    parse_js,
)

_log = logging.getLogger("patchi.agents.modernization")

@register
class ModernizationAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "ModernizationAgent"
    description = "Codemods §7.1.4 var→const, then→await, require→import"
    timeout = 60
    shardable = True
    supported_languages = None

    _MAX_FILES = 500

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        files_scanned = 0
        for pat in ("*.js", "*.jsx", "*.ts", "*.tsx"):
            for fp in get_shard_files(inp, pat):
                if files_scanned >= self._MAX_FILES:
                    break
                rel = fp.relative_to(inp.root).as_posix()
                if "node_modules" in rel:
                    continue
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                lang = lang_for_file(rel)
                tree = parse_js(txt, lang)
                if tree is None:
                    continue
                events = []
                for kind, line in js_var_kinds(tree, lang):
                    if kind == "var":
                        events.append((line, "var"))
                for call in js_calls(tree, lang):
                    if call.name == "then":
                        events.append((call.line, "then"))
                    elif call.name == "require":
                        events.append((call.line, "require"))
                for text, line in js_class_heritages(tree, lang):
                    if "React.Component" in text:
                        events.append((line, "class"))
                events.sort()
                for line, kind in events:
                    if kind == "var":
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=line, title="var → const/let", description="jscodeshift var-to-const: replace var with const/let", finding_type="modernization_var"))
                    elif kind == "then":
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=line, title=".then() → async/await", description="Codemod .then() chain to async/await for readability", finding_type="modernization_then"))
                    elif kind == "require":
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=line, title="require() → import", description="Migrate to ESM import via jscodeshift", finding_type="modernization_require"))
                    elif kind == "class":
                        findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=line, title="Class component → functional", description="Codemod React class to functional + hooks", finding_type="modernization_class"))
                    if len(findings) >= 40:
                        break
                if len(findings) >= 40:
                    break
                files_scanned += 1
            if files_scanned >= self._MAX_FILES:
                break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:40]
