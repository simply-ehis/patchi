"""
LLMSecurityAgent — LLM/Agent prompt injection, insecure output handling, tool abuse.

Detects LLM security issues:
- Direct/indirect prompt injection vectors
- LLM output executed as code, SQL, or rendered as HTML
- Unbounded input lengths / recursive agent loops
- Sensitive data in prompt context
- Untrusted model sources
- Verbose error messages to LLM
- Tool permissions too broad
- Missing human-in-the-loop for destructive actions

Uses static pattern matching, NOT AI.
Does NOT write to disk. Does NOT touch the queue.
"""

from __future__ import annotations

import ast as py_ast
import re

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)


@register
class LLMSecurityAgent(BaseAgent):
    """Detects LLM/agent security vulnerabilities."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "LLMSecurityAgent"
    description = "LLM prompt injection, insecure output handling, tool abuse, excessive agency"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        inp.extra.get("skill_context", {})
        source_patterns = ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx"]

        for pattern in source_patterns:
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                result.files_scanned += 1
                lang = "python" if fpath.suffix == ".py" else "javascript"

                if lang == "python":
                    self._scan_python(content, rel, result)
                else:
                    self._scan_js_ts(content, rel, result)

    def _scan_python(self, content: str, rel: str, result: AgentResult) -> None:
        # ── Prompt injection — user input in system prompt ─────────────────────
        # Part 7: an f-string interpolation is not proof the value is
        # user-controlled — MEDIUM + verify, not HIGH as fact.
        for m in re.finditer(r'(?i)(?:system_prompt|system_message|prompt)\s*=\s*f["\'].*\{', content):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="prompt_injection",
                    severity=Severity.MEDIUM,
                    file=rel,
                    line=content[: m.start()].count("\n") + 1,
                    message="Formatted string in system prompt — verify interpolated values are not user-controlled",
                    suggestion="Use chat template separation with instruction/data delimiters",
                    cwe="CWE-94",
                    extra={"skill": "agent-security-audit.skill"},
                )
            )

        # ── Insecure output — LLM output exec/eval'd ─────────────────────────
        # Part 7: the old alternation (`.*llm|response|result`) matched ANY
        # line containing "response"/"result". Both sides must relate.
        for m in re.finditer(
            r"(?i)(?:exec|eval)\s*\(\s*(?:llm\.|model\.|response|result)\s*[\[\(.]", content
        ):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="insecure_llm_output",
                    severity=Severity.CRITICAL,
                    file=rel,
                    line=content[: m.start()].count("\n") + 1,
                    message="LLM output passed to exec/eval — remote code execution risk",
                    suggestion="Use structured output (Pydantic) with schema validation instead",
                    cwe="CWE-94",
                    extra={"skill": "llm-risk-assess.skill"},
                )
            )

        # ── Recursive agent loop without depth limit ──────────────────────────
        # (The function-self-call AST check below is authoritative; the old
        # regex heuristic referenced a nonexistent \1 capture group and raised
        # "invalid group reference" — removed.)
        try:
            tree = py_ast.parse(content)
            for node in py_ast.walk(tree):
                if isinstance(node, py_ast.FunctionDef):
                    self_name = node.name
                    for child in py_ast.walk(node):
                        if isinstance(child, py_ast.Call) and isinstance(child.func, py_ast.Name):
                            if child.func.id == self_name:
                                # Self-call — check no iteration guard. Part 7:
                                # word-boundary match on real guard names
                                # (max_iter/max_iterations/retries/attempts), not
                                # substrings like "indepth".
                                body_str = content[node.lineno : node.end_lineno] if hasattr(node, "end_lineno") else ""
                                if not re.search(
                                    r"(?i)\b(?:max_iter\w*|max_iterations|retries|attempts|depth_limit|recursion_limit)\b",
                                    body_str,
                                ):
                                    result.add_finding(
                                        Finding(
                                            agent=self.name,
                                            type="recursive_agent_loop",
                                            severity=Severity.MEDIUM,
                                            file=rel,
                                            line=node.lineno,
                                            message=f"Recursive self-call in {self_name} without iteration guard",
                                            suggestion="Add max iteration counter (recommended: 25)",
                                            cwe="CWE-835",
                                        )
                                    )
                                break
        except SyntaxError:
            pass

        # ── Untrusted model source ─────────────────────────────────────────
        # Part 7: from_pretrained/hub.load from the Hub is standard practice,
        # not HIGH as fact; pickle/torch.load of .pt files IS the RCE shape.
        _hub_loads = [
            r'(?i)AutoModel\.from_pretrained\(\s*["\'][^"\']*["\']\s*\)',
            r'(?i)torch\.hub\.load\(\s*["\'][^"\']*["\']\s*\)',
        ]
        _unsafe_loads = [
            r'(?i)torch\.load\(\s*["\'][^"\']*\.pt',
            r"(?i)pickle\.load",
        ]
        for pat in _hub_loads:
            for m in re.finditer(pat, content):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="untrusted_model_source",
                        severity=Severity.MEDIUM,
                        file=rel,
                        line=content[: m.start()].count("\n") + 1,
                        message="Model loaded from Hub — verify origin/pin digest or use safetensors",
                        suggestion="Pin model to SHA256 digest or verify source against allowlist",
                        cwe="CWE-1104",
                        extra={"skill": "llm-risk-assess.skill"},
                    )
                )
        for pat in _unsafe_loads:
            for m in re.finditer(pat, content):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="unsafe_deserialization",
                        severity=Severity.HIGH,
                        file=rel,
                        line=content[: m.start()].count("\n") + 1,
                        message="Pickle/torch.load deserialization — arbitrary code execution risk",
                        suggestion="Use safetensors or another safe serialization format",
                        cwe="CWE-502",
                        extra={"skill": "llm-risk-assess.skill"},
                    )
                )

        # ── Sensitive data in prompt context ────────────────────────────────
        # Part 7: keyword-near-llm is MEDIUM + verify, not HIGH as fact.
        for m in re.finditer(
            r'(?i)(?:db_url|api_key|password|\bsecret\b|\btoken\b).*llm\.|context.*=.*f["\']',
            content,
        ):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="sensitive_data_in_prompt",
                    severity=Severity.MEDIUM,
                    file=rel,
                    line=content[: m.start()].count("\n") + 1,
                    message="Sensitive data potentially passed to LLM context — verify and redact",
                    suggestion="Filter or redact secrets before LLM call",
                    cwe="CWE-200",
                    extra={"skill": "llm-risk-assess.skill"},
                )
            )

        # ── Tool permissions too broad ──────────────────────────────────────
        for m in re.finditer(r'(?i)permissions?\s*=\s*\["read"[,\s]*"write"[,\s]*"execute"\]', content):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="excessive_tool_permissions",
                    severity=Severity.MEDIUM,
                    file=rel,
                    line=content[: m.start()].count("\n") + 1,
                    message="Tool has read+write+execute — apply least privilege",
                    suggestion="Restrict permissions per tool; use granular scopes",
                    cwe="CWE-269",
                    extra={"skill": "agent-security-audit.skill"},
                )
            )

        # ── Auto-approve destructive actions ───────────────────────────────
        # Part 7: a confirmation gate on nearby lines exonerates; CRITICAL
        # requires its absence, else HIGH + verify (a gate may live elsewhere).
        for m in re.finditer(r'(?i)agent\.run\(\s*["\'](?:delete|drop|remove|destroy)', content):
            line_no = content[: m.start()].count("\n") + 1
            window = "\n".join(content.splitlines()[max(0, line_no - 6):line_no + 2])
            if re.search(r"(?i)(?:confirm|approv|human|review|gate|allowlist|whitelist)", window):
                continue
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="excessive_agency",
                    severity=Severity.HIGH,
                    file=rel,
                    line=line_no,
                    message="Destructive action with no confirmation gate visible nearby — verify human approval",
                    suggestion="Implement confirmation gate for DELETE/DROP/REMOVE operations",
                    cwe="CWE-862",
                    extra={"skill": "agent-security-audit.skill"},
                )
            )

    def _scan_js_ts(self, content: str, rel: str, result: AgentResult) -> None:
        # ── LLM output rendered as HTML ─────────────────────────────────────
        # Part 7: the old alternation matched ANY line with "response" in
        # it. Sink AND source must share the line (either order).
        for m in re.finditer(
            r"(?i)(?:innerHTML|outerHTML|\.html\(|dangerouslySetInnerHTML)[^;\n]*(?:llm|response|result)"
            r"|(?:llm|response|result)[^;\n]*(?:innerHTML|outerHTML|\.html\(|dangerouslySetInnerHTML)",
            content,
        ):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="insecure_llm_output_rendering",
                    severity=Severity.HIGH,
                    file=rel,
                    line=content[: m.start()].count("\n") + 1,
                    message="LLM output rendered as HTML without sanitization",
                    suggestion="Use textContent or DOMPurify sanitization",
                    cwe="CWE-79",
                    extra={"skill": "agent-security-audit.skill"},
                )
            )

        # ── Tool shell injection (no validation) ───────────────────────────
        # Part 7: shell:true is HIGH only with user-controlled input on the
        # line; otherwise MEDIUM config smell with verify language.
        for m in re.finditer(r"(?i)shell\s*:\s*true|shell\s*=\s*true", content):
            line_no = content[: m.start()].count("\n") + 1
            line_text = content.splitlines()[line_no - 1] if line_no <= len(content.splitlines()) else ""
            has_input = bool(re.search(r"(?i)(?:input|user|arg|param|query|prompt)", line_text))
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="tool_shell_injection",
                    severity=Severity.HIGH if has_input else Severity.MEDIUM,
                    file=rel,
                    line=line_no,
                    message="Tool uses shell=true with user-controlled input"
                    if has_input
                    else "Tool uses shell=true — verify inputs are validated/allowlisted",
                    suggestion="Use subprocess without shell=True, validate input against allowlist",
                    cwe="CWE-78",
                    extra={"skill": "agent-security-audit.skill"},
                )
            )
