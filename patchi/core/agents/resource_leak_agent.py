"""
ResourceLeakAgent §7.3.1-3 — setInterval/setTimeout/EventEmitter without cleanup, useEffect without cleanup, file handle not closed.

Tree-sitter pattern: setInterval without clearInterval in same scope; useEffect return missing; createReadStream without close/destroy.
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

_log = logging.getLogger("patchi.agents.resource_leak")

_INTERVAL_RE = re.compile(r"setInterval\s*\(")
_TIMEOUT_RE = re.compile(r"setTimeout\s*\(")
_EMITTER_RE = re.compile(r"\.on\s*\(\s*['\"]\w+['\"]\s*,")
_USEEFFECT_RE = re.compile(r"useEffect\s*\(")
_STREAM_RE = re.compile(r"createReadStream|createWriteStream|fs\.open")

@register
class ResourceLeakAgent(BaseAgent):
    group = AgentGroup.SCANNER
    name = "ResourceLeakAgent"
    description = "Resource leak §7.3 setInterval/EventEmitter/useEffect/stream without cleanup"
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings=[]
        for pat in ("*.js","*.jsx","*.ts","*.tsx"):
            for fp in safe_rglob(inp.root, pat):
                rel=fp.relative_to(inp.root).as_posix()
                if "node_modules" in rel or "tests" in rel:
                    continue
                try:
                    txt=fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                lines=txt.splitlines()
                has_interval = any(_INTERVAL_RE.search(line) for line in lines)
                has_clear = any("clearInterval" in line for line in lines)
                has_emitter = any(_EMITTER_RE.search(line) for line in lines)
                has_off = "removeListener" in txt or "off(" in txt or "removeEventListener" in txt
                has_effect = any(_USEEFFECT_RE.search(line) for line in lines)
                has_effect_cleanup = "return () =>" in txt or "return function" in txt
                has_stream = any(_STREAM_RE.search(line) for line in lines)
                has_close = ".close(" in txt or ".destroy(" in txt or ".end(" in txt

                # Interval leak
                if has_interval and not has_clear:
                    for i, line in enumerate(lines,1):
                        if _INTERVAL_RE.search(line):
                            findings.append(make_finding(severity=Severity.MEDIUM, file=rel, line_start=i, title="setInterval without clearInterval", description="Leaks interval; store handle and clearInterval on unmount/cleanup", finding_type="resource_leak_interval"))
                            break
                # Emitter leak
                if has_emitter and not has_off:
                    for i, line in enumerate(lines,1):
                        if _EMITTER_RE.search(line):
                            findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="EventEmitter .on without off/cleanup", description="Add removeListener/off in cleanup", finding_type="resource_leak_emitter"))
                            break
                # useEffect without cleanup
                if has_effect and not has_effect_cleanup and has_interval:
                    for i, line in enumerate(lines,1):
                        if _USEEFFECT_RE.search(line):
                            findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="useEffect with interval but no cleanup return", description="Return () => clearInterval in useEffect", finding_type="resource_leak_effect"))
                            break
                # Stream not closed
                if has_stream and not has_close:
                    for i, line in enumerate(lines,1):
                        if _STREAM_RE.search(line):
                            findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=i, title="Stream without close/destroy", description="Ensure fs stream closed/destroyed", finding_type="resource_leak_stream"))
                            break
                if len(findings) >= 40:
                    break
            if len(findings) >= 40:
                break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:40]
