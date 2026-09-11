"""RefactoringAgent — resource leaks, cleanup hygiene, modernization.

Covers §7.1.3-4 and §7.3.1-3:
- Dependency sorting (isort, goimports, rustfmt)
- Modernization patterns (var→const/let, .then()→async/await, require→import)
- Resource leak detection (setInterval without clearInterval)
- React effect cleanup (useEffect without cleanup)
- File handle tracking (streams without close)
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from ..brain.code_query import (
    js_call_names,
    js_calls,
    js_useeffect_without_cleanup,
    lang_for_file,
    parse_js,
)
from ..brain.languages import DEFAULT_IGNORE_DIRS
from .base import (
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

_log = logging.getLogger("patchi.agents.refactoring_agent")


def _detect_interval_without_cleanup(content: str, lang: str) -> list[dict]:
    findings: list[dict] = []
    tree = parse_js(content, lang)
    if tree is None:
        return findings
    names = js_call_names(tree, lang)
    if "setInterval" in names and "clearInterval" not in names:
        for call in js_calls(tree, lang):
            if call.name == "setInterval":
                findings.append({"line": call.line, "type": "setInterval"})
                break
    return findings


def _detect_effect_without_cleanup(content: str, lang: str) -> list[dict]:
    return [
        {"line": line, "type": "useEffect_no_cleanup"}
        for line in js_useeffect_without_cleanup(parse_js(content, lang), lang)
    ]


def _detect_py_file_handle_leaks(content: str) -> list[dict]:
    """Python open() outside a with-statement, via stdlib ast."""
    findings: list[dict] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    def _is_open(node) -> bool:
        return isinstance(node, ast.Call) and getattr(node.func, "id", "") == "open"

    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                for n in ast.walk(item.context_expr):
                    if _is_open(n):
                        guarded.add(n.lineno)
    for node in ast.walk(tree):
        if _is_open(node) and node.lineno not in guarded:
            findings.append({"line": node.lineno, "resource": "open()", "type": "file_handle"})
    return findings


def _detect_file_handle_leaks(content: str, lang: str) -> list[dict]:
    findings: list[dict] = []
    tree = parse_js(content, lang)
    if tree is None:
        return findings
    names = js_call_names(tree, lang)
    opened = [c for c in js_calls(tree, lang) if c.name in ("createReadStream", "createWriteStream") or c.full == "fs.open"]
    if opened and not names & {"close", "destroy", "end"}:
        first = opened[0]
        findings.append({"line": first.line, "resource": first.full or first.name, "type": "file_handle"})
    return findings


def _detect_file_handle_leaks_legacy(content: str) -> list[dict]:
    """Fallback for languages without an installed tree-sitter grammar.

    Regex is the only available tool here (no parser installed); kept
    deliberately narrow and documented.
    """
    import re

    findings: list[dict] = []
    lines = content.splitlines()
    streams: dict[str, int] = {}
    for i, line in enumerate(lines):
        for pat in [
            r"(?:createReadStream|createWriteStream)\s*\(\s*([^)]+)\)",
            r"open\s*\(\s*['\"]([^'\"]+)",
        ]:
            m = re.search(pat, line)
            if m:
                ident = m.group(1)[:20]
                streams[ident] = i + 1
        if re.search(r"\.(close|destroy|end)\s*\(", line):
            for k in list(streams.keys()):
                streams.pop(k, None)
    for ident, line in streams.items():
        findings.append({"line": line, "resource": ident, "type": "file_handle"})
    return findings


def _detect_modernization_candidates(content: str, ext: str, lang: str) -> list[dict]:
    findings: list[dict] = []
    tree = parse_js(content, lang)
    if tree is None:
        return findings
    from ..brain.code_query import js_var_kinds

    lines = content.splitlines()
    for kind, line in js_var_kinds(tree, lang):
        if kind == "var":
            text = lines[line - 1].strip()[:60] if 0 < line <= len(lines) else ""
            findings.append({"line": line, "type": "var_to_const_let", "text": text})
    for call in js_calls(tree, lang):
        if call.name != "then":
            continue
        text = lines[call.line - 1] if 0 < call.line <= len(lines) else ""
        if "async" in text or "await" in text:
            continue
        findings.append({"line": call.line, "type": "then_to_async_await", "text": text.strip()[:60]})
    if "require" in js_call_names(tree, lang) and "import " not in content:
        for call in js_calls(tree, lang):
            if call.name == "require":
                text = lines[call.line - 1] if 0 < call.line <= len(lines) else ""
                findings.append({"line": call.line, "type": "require_to_import", "text": text.strip()[:60]})
    return findings


@register
class RefactoringAgent(BaseAgent):
    """Detects resource leaks, missing cleanup, and modernization opportunities."""

    group = AgentGroup.SCANNER
    name = "RefactoringAgent"
    description = "Resource leaks, React effect cleanup, file handles, modernization patterns"
    shardable = True
    supported_languages = None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        interval_leaks: list[dict] = []
        effect_issues: list[dict] = []
        file_handle_leaks: list[dict] = []
        modernization: list[dict] = []
        files_scanned = 0

        # Use corpus if available, else rglob
        _REF_EXT = {".js", ".jsx", ".ts", ".tsx", ".py", ".rs", ".go", ".java",
                    ".c", ".cpp", ".swift", ".rb", ".svelte"}
        _MAX_FILES = 200
        corpus = inp.extra.get("file_corpus")
        if corpus and corpus.entries:
            file_iter = ((inp.root / k, k) for k in corpus.entries)
        else:
            file_iter = ((fp, fp.relative_to(inp.root).as_posix()) for fp in get_shard_files(inp, "*"))

        count = 0
        for file_path, rel in file_iter:
            if count >= _MAX_FILES:
                break
            if any(seg in DEFAULT_IGNORE_DIRS for seg in Path(rel).parts):
                continue
            ext = file_path.suffix.lower()
            if ext not in _REF_EXT:
                continue
            files_scanned += 1
            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception as e:
                _log.warning("RefactoringAgent._run failed: %s", e)
                continue

            if ext in (".js", ".jsx", ".ts", ".tsx", ".svelte"):
                lang = lang_for_file(rel)
                interval_leaks.extend(
                    {"file": rel, **f} for f in _detect_interval_without_cleanup(content, lang)
                )
                effect_issues.extend(
                    {"file": rel, **f} for f in _detect_effect_without_cleanup(content, lang)
                )
                modernization.extend(
                    {"file": rel, **f} for f in _detect_modernization_candidates(content, ext, lang)
                )

            if ext in (".js", ".jsx", ".ts", ".tsx"):
                file_handle_leaks.extend(
                    {"file": rel, **f}
                    for f in _detect_file_handle_leaks(content, lang_for_file(rel))
                )
            elif ext == ".py":
                file_handle_leaks.extend(
                    {"file": rel, **f} for f in _detect_py_file_handle_leaks(content)
                )
            elif ext in (".rs", ".go", ".java", ".c", ".cpp"):
                file_handle_leaks.extend(
                    {"file": rel, **f} for f in _detect_file_handle_leaks_legacy(content)
                )
            count += 1

        result.data["interval_leaks"] = interval_leaks
        result.data["effect_issues"] = effect_issues
        result.data["file_handle_leaks"] = file_handle_leaks
        result.data["modernization"] = modernization

        for f in interval_leaks:
            result.findings.append(
                make_finding(
                    self.name,
                    "resource_leak",
                    Severity.MEDIUM,
                    f["file"],
                    f"Resource leak: {f['type']} without matching clearInterval",
                    line=f["line"],
                    suggestion="Assign setInterval to a variable and call clearInterval() on unmount",
                )
            )
        for f in effect_issues:
            result.findings.append(
                make_finding(
                    self.name,
                    "effect_cleanup",
                    Severity.MEDIUM,
                    f["file"],
                    "useEffect without cleanup function",
                    line=f["line"],
                    detail="Subscriptions/timers in useEffect must return a cleanup function",
                    suggestion="Add a return cleanup function to prevent memory leaks",
                )
            )
        for f in file_handle_leaks:
            result.findings.append(
                make_finding(
                    self.name,
                    "file_handle_leak",
                    Severity.MEDIUM,
                    f["file"],
                    f"Potential file handle leak: {f.get('resource', '?')}",
                    line=f["line"],
                    detail="Stream/file opened without matching close/destroy",
                    suggestion="Ensure .close() or .destroy() is called in all code paths",
                )
            )
        for f in modernization:
            type_labels = {
                "var_to_const_let": "Replace var with const/let",
                "then_to_async_await": "Consider using async/await instead of .then()",
                "require_to_import": "Replace require() with import statement",
            }
            result.findings.append(
                make_finding(
                    self.name,
                    f["type"],
                    Severity.LOW,
                    f["file"],
                    type_labels.get(f["type"], f["type"]),
                    line=f["line"],
                    detail=f["text"],
                    suggestion="Apply modernization codemod",
                )
            )

        result.files_scanned = files_scanned
        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
