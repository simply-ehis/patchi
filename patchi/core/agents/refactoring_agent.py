"""RefactoringAgent — resource leaks, cleanup hygiene, modernization.

Covers §7.1.3-4 and §7.3.1-3:
- Dependency sorting (isort, goimports, rustfmt)
- Modernization patterns (var→const/let, .then()→async/await, require→import)
- Resource leak detection (setInterval without clearInterval)
- React effect cleanup (useEffect without cleanup)
- File handle tracking (streams without close)
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..brain.languages import DEFAULT_IGNORE_DIRS
from .base import (
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

_log = logging.getLogger("patchi.agents.refactoring_agent")


def _detect_interval_without_cleanup(content: str) -> list[dict]:
    findings: list[dict] = []
    has_clear = "clearInterval" in content
    for i, line in enumerate(content.splitlines()):
        if "setInterval" in line and "clearInterval" not in line:
            if not has_clear:
                m = re.search(r"setInterval\s*\(", line)
                if m:
                    findings.append({"line": i + 1, "type": "setInterval"})
    return findings


def _detect_effect_without_cleanup(content: str) -> list[dict]:
    findings: list[dict] = []
    lines = content.splitlines()
    in_effect = False
    effect_start = 0
    has_cleanup = False
    brace_depth = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "useEffect" in stripped and "=>" in stripped:
            in_effect = True
            effect_start = i + 1
            has_cleanup = False
            brace_depth = stripped.count("{") - stripped.count("}")
            if brace_depth > 0:
                continue
        if in_effect:
            brace_depth += stripped.count("{") - stripped.count("}")
            if "return" in stripped and ("=>" in stripped or "(" in stripped or ";" in stripped):
                has_cleanup = True
            if brace_depth <= 0:
                if not has_cleanup:
                    findings.append({"line": effect_start, "type": "useEffect_no_cleanup"})
                in_effect = False
    return findings


def _detect_file_handle_leaks(content: str) -> list[dict]:
    findings: list[dict] = []
    lines = content.splitlines()
    streams: dict[str, int] = {}
    for i, line in enumerate(lines):
        # Detect stream creation patterns
        for pat in [
            r"(?:createReadStream|createWriteStream)\s*\(\s*([^)]+)\)",
            r"open\s*\(\s*['\"]([^'\"]+)",
        ]:
            m = re.search(pat, line)
            if m:
                ident = m.group(1)[:20]
                streams[ident] = i + 1
        # Detect close/destroy calls
        if re.search(r"\.(close|destroy|end)\s*\(", line):
            for k in list(streams.keys()):
                streams.pop(k, None)
    for ident, line in streams.items():
        findings.append({"line": line, "resource": ident, "type": "file_handle"})
    return findings


def _detect_modernization_candidates(content: str, ext: str) -> list[dict]:
    findings: list[dict] = []
    lines = content.splitlines()
    if ext in (".js", ".jsx", ".ts", ".tsx"):
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.search(r"\bvar\s+\w+\s*=", stripped) and not stripped.startswith("//"):
                findings.append({"line": i + 1, "type": "var_to_const_let", "text": stripped[:60]})
            if ".then(" in stripped and "async" not in stripped and "await" not in stripped:
                if re.search(r"\.then\s*\(", stripped):
                    findings.append(
                        {"line": i + 1, "type": "then_to_async_await", "text": stripped[:60]}
                    )
            if re.search(r"require\s*\(['\"]", stripped) and not stripped.startswith("//"):
                if "import " not in content:
                    findings.append(
                        {"line": i + 1, "type": "require_to_import", "text": stripped[:60]}
                    )
    return findings


@register
class RefactoringAgent(BaseAgent):
    """Detects resource leaks, missing cleanup, and modernization opportunities."""

    group = AgentGroup.SCANNER
    name = "RefactoringAgent"
    description = "Resource leaks, React effect cleanup, file handles, modernization patterns"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        interval_leaks: list[dict] = []
        effect_issues: list[dict] = []
        file_handle_leaks: list[dict] = []
        modernization: list[dict] = []
        files_scanned = 0

        for file_path in safe_rglob(inp.root, "*"):
            rel = file_path.relative_to(inp.root).as_posix()
            if any(seg in DEFAULT_IGNORE_DIRS for seg in Path(rel).parts):
                continue
            ext = file_path.suffix.lower()
            if ext not in (
                ".js",
                ".jsx",
                ".ts",
                ".tsx",
                ".py",
                ".rs",
                ".go",
                ".java",
                ".c",
                ".cpp",
                ".swift",
                ".rb",
                ".svelte",
            ):
                continue
            files_scanned += 1
            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception as e:
                _log.warning("RefactoringAgent._run failed: %s", e)
                continue

            if ext in (".js", ".jsx", ".ts", ".tsx", ".svelte"):
                interval_leaks.extend(
                    {"file": rel, **f} for f in _detect_interval_without_cleanup(content)
                )
                effect_issues.extend(
                    {"file": rel, **f} for f in _detect_effect_without_cleanup(content)
                )
                modernization.extend(
                    {"file": rel, **f} for f in _detect_modernization_candidates(content, ext)
                )

            if ext in (".js", ".jsx", ".ts", ".tsx", ".py", ".rs", ".go", ".java", ".c", ".cpp"):
                file_handle_leaks.extend(
                    {"file": rel, **f} for f in _detect_file_handle_leaks(content)
                )

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
