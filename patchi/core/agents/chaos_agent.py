"""
ChaosAgent §5.3.3-4 — Race Condition + Chaos Testing.

Race: concurrent duplicate requests to same endpoint → duplicate records.
Chaos: missing retry/backoff on network, no circuit breaker.
"""

from __future__ import annotations

import ast
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
)
from patchi.core.brain.code_query import (
    js_calls,
    js_identifiers,
    js_string_literals,
    lang_for_file,
    parse_js,
)

_log = logging.getLogger("patchi.agents.chaos")

_RACE_WORDS = ("create", "insert", "update", "upsert", "transaction")
_RETRY_WORDS = ("retry", "backoff", "circuit", "breaker", "tenacity", "resilience")


def _py_tokens(content: str) -> tuple[set[str], set[str], list[tuple[str, int]]]:
    """(call names, word tokens, [(call, line)]) for Python via stdlib ast."""
    calls: list[tuple[str, int]] = []
    words: set[str] = set()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return set(), set(), []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name:
                calls.append((name, node.lineno))
                words.add(name.lower())
        elif isinstance(node, ast.Name):
            words.add(node.id.lower())
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            words.add(node.name.lower())
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for word in node.value.lower().split():
                words.add(word.strip(".,:;!?()[]{}\"'"))
    return {c[0] for c in calls}, words, calls


def _has_race_words(words: set[str]) -> bool:
    return any(any(rw in w for w in words) for rw in _RACE_WORDS)


def _has_retry_words(words: set[str]) -> bool:
    return any(any(rw in w for w in words) for rw in _RETRY_WORDS)

@register
class ChaosAgent(BaseAgent):
    group = AgentGroup.TEST
    name = "ChaosAgent"
    description = "Race duplicate requests + Chaos missing retry/backoff §5.3.3-4"
    timeout = 60
    shardable = True
    supported_languages = None

    _MAX_FILES = 500

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        files_scanned = 0
        for pat in ("*.py", "*.js", "*.ts"):
            for fp in get_shard_files(inp, pat):
                if files_scanned >= self._MAX_FILES:
                    break
                rel = fp.relative_to(inp.root).as_posix()
                if "tests" in rel or "node_modules" in rel:
                    continue
                try:
                    txt = fp.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if fp.suffix == ".py":
                    _, words, calls = _py_tokens(txt)
                    open_lines = [ln for n, ln in calls if n == "open"]
                    net_lines = [
                        ln for n, ln in calls if n in ("get", "post", "request", "urlopen")
                    ]
                else:
                    lang = lang_for_file(rel)
                    tree = parse_js(txt, lang)
                    if tree is None:
                        continue
                    words = {i.lower() for i in js_identifiers(tree, lang)}
                    words |= {s.lower() for s, _ in js_string_literals(tree, lang)}
                    js_call_list = js_calls(tree, lang)
                    open_lines = [c.line for c in js_call_list if c.name == "open"]
                    net_lines = [
                        c.line for c in js_call_list
                        if c.full == "fetch" or c.full.startswith("axios.")
                    ]
                # Race: file write without lock/atomic
                if open_lines and not words & {"lock", "atomic", "mutex"}:
                    if _has_race_words(words):
                        findings.append(make_finding(
                            severity=Severity.MEDIUM, file=rel, line_start=open_lines[0],
                            title="Possible race — file write without lock",
                            description=(
                                "Concurrent requests may duplicate records; "
                                "use atomic write or DB transaction"
                            ),
                            finding_type="race_file_write",
                        ))
                # Chaos: fetch without retry
                if len(net_lines) > 2 and not _has_retry_words(words):
                    findings.append(make_finding(
                        severity=Severity.LOW, file=rel, line_start=0,
                        title="No retry/backoff on network calls",
                        description="Add retry with backoff + circuit breaker for chaos resilience",
                        finding_type="chaos_no_retry",
                    ))
                files_scanned += 1
                if len(findings) >= 20:
                    break
            if files_scanned >= self._MAX_FILES:
                break
        result.status=AgentStatus.SUCCEEDED
        result.findings=findings[:20]
