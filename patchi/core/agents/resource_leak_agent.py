"""
ResourceLeakAgent §7.3.1-3 — setInterval/setTimeout/EventEmitter without cleanup, useEffect without cleanup, file handle not closed.

Tree-sitter pattern: setInterval without clearInterval in same scope; useEffect return missing; createReadStream without close/destroy.
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
    make_finding,
    register,
    safe_rglob,
)
from patchi.core.brain.code_query import (
    js_calls,
    js_useeffect_without_cleanup,
    lang_for_file,
    parse_js,
)

_log = logging.getLogger("patchi.agents.resource_leak")

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
                tree=parse_js(txt, lang_for_file(rel))
                if tree is None:
                    continue
                calls=js_calls(tree, lang_for_file(rel))
                names={c.name for c in calls}
                by_name: dict[str, list] = {}
                for c in calls:
                    by_name.setdefault(c.name, []).append(c)
                first_interval = by_name["setInterval"][0].line if "setInterval" in by_name else 0

                has_interval = "setInterval" in names
                has_clear = "clearInterval" in names
                has_emitter = any(
                    c.name == "on" and c.arg_kinds[:1] == ["string"] for c in calls
                )
                has_off = bool(names & {"removeListener", "off", "removeEventListener"})
                no_cleanup_lines = js_useeffect_without_cleanup(tree, lang_for_file(rel))
                stream_call = next(
                    (c for c in calls if c.name in ("createReadStream", "createWriteStream") or c.full == "fs.open"),
                    None,
                )
                has_stream = stream_call is not None
                has_close = bool(names & {"close", "destroy", "end"})

                # Interval leak
                if has_interval and not has_clear:
                    findings.append(make_finding(severity=Severity.MEDIUM, file=rel, line_start=first_interval, title="setInterval without clearInterval", description="Leaks interval; store handle and clearInterval on unmount/cleanup", finding_type="resource_leak_interval"))
                # Emitter leak
                if has_emitter and not has_off:
                    line = next((c.line for c in calls if c.name == "on" and c.arg_kinds[:1] == ["string"]), 0)
                    findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=line, title="EventEmitter .on without off/cleanup", description="Add removeListener/off in cleanup", finding_type="resource_leak_emitter"))
                # useEffect without cleanup
                if no_cleanup_lines and has_interval:
                    findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=no_cleanup_lines[0], title="useEffect with interval but no cleanup return", description="Return () => clearInterval in useEffect", finding_type="resource_leak_effect"))
                # Stream not closed
                if has_stream and not has_close and stream_call is not None:
                    findings.append(make_finding(severity=Severity.LOW, file=rel, line_start=stream_call.line, title="Stream without close/destroy", description="Ensure fs stream closed/destroyed", finding_type="resource_leak_stream"))
                if len(findings) >= 40:
                    break
            if len(findings) >= 40:
                break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:40]
