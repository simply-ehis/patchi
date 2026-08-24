"""
CatchBlockAuditor — Detects empty or bare catch/except blocks.

Finds error handlers that swallow exceptions:
  - Empty catch/except blocks: `catch (e) {}` or `except: pass`
  - Bare logging without re-raise: `catch (e) { console.log(e); }`
  - Swallowed exceptions with no action: `catch {}`
  - Silent failure: bare `except:` without specifying exception type

Covers all languages with tree-sitter via AST walkers where a try/catch
construct exists; Go (ignored `err`) and Rust (`unwrap`) are handled with
targeted checks since they have no exception-handling blocks.

Uses AST structure (accurate block boundaries) + lightweight text analysis
of the handler body to decide whether it does something useful.
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations
import logging

import re
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
)
from ..brain.ast_utils import (
    child_by_field,
    find_assignments,
    find_calls,
    named_children,
    node_text,
    parse_source,
)
from ..brain.languages import EXTENSION_MAP, Lang
from ..brain.trace_log import trace_agent

# Tree-sitter node types that represent an exception-handling block, per language.
CATCH_NODE_TYPES: dict[Lang, set[str]] = {
    Lang.PYTHON: {"except_clause"},
    Lang.JAVASCRIPT: {"catch_clause"},
    Lang.TYPESCRIPT: {"catch_clause"},
    Lang.JAVA: {"catch_clause"},
    Lang.C_SHARP: {"catch_clause"},
    Lang.CPP: {"catch_clause"},
    Lang.KOTLIN: {"catch_block"},
    Lang.SWIFT: {"catch_block"},
    Lang.RUBY: {"rescue"},
}

# Body node types that hold the handler statements (fallback when no field name).
_BODY_TYPES = {"block", "compound_statement", "statement_block", "then", "statements"}

# Line-level heuristics for deciding whether a handler body does something useful.
_SINGLE_IDENT_RE = re.compile(r"^[a-zA-Z_]\w*$")
_CONSOLE_LOG_RE = re.compile(r"console\.(log|warn)\([^)]*\)")
_PRINT_RE = re.compile(r"print\([^)]*\)")
_P_RE = re.compile(r"p\s+[^)]+")
_TRACEBACK_RE = re.compile(r"(traceback\.print_exc|print_exc|e\.printStackTrace)")


_log = logging.getLogger("patchi.security.catch_block_auditor")


@register
class CatchBlockAuditor(BaseAgent):
    """Agent for detecting empty or insufficient catch/except blocks."""

    group = AgentGroup.SECURITY
    name = "CatchBlockAuditor"
    description = "Empty or bare catch/except blocks that swallow exceptions"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []

        source_patterns = [
            "*.py", "*.js", "*.jsx", "*.ts", "*.tsx",
            "*.java", "*.go", "*.rs", "*.c", "*.h",
            "*.cpp", "*.cxx", "*.cc", "*.hpp", "*.rb",
            "*.swift", "*.kt", "*.kts", "*.cs",
        ]

        with trace_agent(self.name, inp.root) as trace:
            for pattern in source_patterns:
                for file_path in safe_rglob(inp.root, pattern):
                    if file_path.is_file():
                        rel_path = file_path.relative_to(inp.root).as_posix()
                        if not self._should_skip_file(rel_path, inp):
                            ext = file_path.suffix.lower()
                            content = self._safe_read(file_path)
                            if content is None:
                                continue
                            findings.extend(self._scan_catch_blocks(content, rel_path, ext))
            trace.findings = len(findings)

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update({"catch_block_findings": len(findings), "needs_ai": False})
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        from pathlib import PurePosixPath

        restrictions = inp.config.get("restrictions", [])
        for r in restrictions:
            if r.get("enabled", True):
                path = r["path"]
                if file_path.startswith(path) or PurePosixPath(file_path).match(path):
                    if r["type"] == "NO_TOUCH":
                        return True
                    if r["type"] == "SCAN_ONLY" and self.__class__.__name__ == "FixAgent":
                        return True
        return False

    def _safe_read(self, path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8")
        except Exception as e:
            _log.warning("CatchBlockAuditor._safe_read failed: %s", e)
            return None

    # ── Dispatch ─────────────────────────────────────────────────────────────

    def _scan_catch_blocks(self, content: str, rel_path: str, ext: str) -> list[Finding]:
        lang = EXTENSION_MAP.get(ext)
        if lang is None:
            return []

        # Go and Rust have no exception-handling blocks — handle idiomatically.
        if lang == Lang.GO:
            return self._scan_go(content, rel_path)
        if lang == Lang.RUST:
            return self._scan_rust(content, rel_path)

        node_types = CATCH_NODE_TYPES.get(lang)
        if not node_types:
            return []

        tree = parse_source(content, lang)
        if tree is None:
            return []

        findings = self._walk_catch_tree(tree.root_node, node_types, lang, rel_path)
        if lang == Lang.JAVA:
            findings.extend(self._scan_java_printstacktrace(content, rel_path))
        return findings

    # ── AST walking ──────────────────────────────────────────────────────────

    def _walk_catch_tree(self, node, node_types: set[str], lang: Lang, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        if node.type in node_types:
            spec, is_bare, body_text = self._classify_catch(node, lang)
            line = node.start_point[0] + 1
            if is_bare:
                findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line_start=line,
                        title="Bare except clause" if lang == Lang.PYTHON else "Bare catch clause",
                        description=(
                            "A catch/except handler without an exception type catches everything "
                            "(including control-flow exceptions). Specify the expected exception type(s) "
                            "to avoid swallowing critical errors."
                        ),
                        evidence=node_text(node).strip(),
                        cwe="CWE-755",
                    )
                )
            elif not body_text.strip():
                findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line_start=line,
                        title="Empty catch block",
                        description=(
                            "Catch block is empty. Exceptions are silently swallowed. "
                            "Add error handling, logging, or re-throw."
                        ),
                        evidence=node_text(node).strip(),
                        cwe="CWE-755",
                    )
                )
            elif self._is_bare_catch(body_text):
                findings.append(
                    make_finding(
                        severity=Severity.LOW,
                        file=rel_path,
                        line_start=line,
                        title="Insufficient catch block",
                        description=(
                            f"Exception handler for '{spec}' only logs or prints without recovery. "
                            "Consider adding proper error handling, fallback, or re-raise."
                        ),
                        evidence=node_text(node).strip(),
                        cwe="CWE-755",
                    )
                )
        for child in node.children:
            findings.extend(self._walk_catch_tree(child, node_types, lang, rel_path))
        return findings

    def _classify_catch(self, node, lang: Lang) -> tuple[str, bool, str]:
        """Return (exception_spec_text, is_bare, body_text)."""
        body_node = None
        for field in ("body", "statements"):
            b = child_by_field(node, field)
            if b is not None:
                body_node = b
                break
        if body_node is None:
            for c in named_children(node):
                if c.type in _BODY_TYPES:
                    body_node = c
                    break
        body_text = node_text(body_node) if body_node is not None else ""
        # Strip the surrounding braces so the inner statements are analysed.
        stripped = body_text.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            inner = stripped[1:-1]
            body_text = inner

        if lang == Lang.PYTHON:
            val = child_by_field(node, "value")
            is_bare = val is None
            spec = node_text(val) if val is not None else "bare except"
        elif lang in (Lang.JAVASCRIPT, Lang.TYPESCRIPT):
            param = child_by_field(node, "parameter")
            is_bare = param is None
            spec = node_text(param) if param is not None else "bare catch"
        elif lang in (Lang.JAVA, Lang.C_SHARP):
            cfp = None
            for c in named_children(node):
                if c.type in ("catch_formal_parameter", "catch_declaration"):
                    cfp = c
                    break
            spec = node_text(cfp) if cfp is not None else "catch"
            is_bare = False
        elif lang == Lang.CPP:
            params = child_by_field(node, "parameters")
            ptext = node_text(params) if params is not None else ""
            is_bare = ptext.strip() == "..."
            spec = ptext or "catch"
        elif lang == Lang.KOTLIN:
            spec = node_text(node)
            is_bare = False
        elif lang == Lang.SWIFT:
            err = child_by_field(node, "error")
            is_bare = err is None
            spec = node_text(err) if err is not None else "bare catch"
        elif lang == Lang.RUBY:
            ex = child_by_field(node, "exceptions")
            is_bare = ex is None
            spec = node_text(ex) if ex is not None else "bare rescue"
        else:
            spec = node_text(node)
            is_bare = False
        return spec, is_bare, body_text

    def _scan_java_printstacktrace(self, content: str, rel_path: str) -> list[Finding]:
        from ..brain.ast_utils import find_calls

        findings: list[Finding] = []
        for m in find_calls(content, Lang.JAVA, {"printStackTrace"}):
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=m.get("line", 0),
                    title="Bare printStackTrace()",
                    description=(
                        "e.printStackTrace() writes to stderr but is often lost in production. "
                        "Use a logging framework (SLF4J, Log4j) instead."
                    ),
                    evidence=m.get("full_text", "printStackTrace()").strip(),
                    cwe="CWE-755",
                )
            )
        return findings

    # ── Body usefulness analysis (text-based) ────────────────────────────────

    def _is_bare_catch(self, block_body: str) -> bool:
        """Check if a catch block body contains only trivial/no-op statements."""
        stripped = block_body.strip().rstrip(";")
        if not stripped:
            return True
        noop_lines = [
            l.strip().rstrip(";")
            for l in stripped.split("\n")
            if l.strip() and not l.strip().startswith(("#", "//", "/*", "*"))
        ]
        if not noop_lines:
            return True
        for line in noop_lines:
            if not self._is_noop_line(line):
                return False
        return True

    def _is_noop_line(self, line: str) -> bool:
        """Check if a line is a no-op in exception handling."""
        line = line.strip().rstrip(";")
        if not line:
            return True
        # Single identifiers (bare variable names like `error`)
        if _SINGLE_IDENT_RE.match(line):
            return True
        # Pass, next, nil, None, null, undefined
        if line in ("pass", "next", "nil", "None", "null", "undefined"):
            return True
        # Bare console.log/print of the error
        if _CONSOLE_LOG_RE.match(line):
            return True
        if _PRINT_RE.match(line):
            return True
        if _P_RE.match(line):
            return True
        # Bare traceback/stack print
        if _TRACEBACK_RE.match(line):
            return True
        return False

    # ── Go / Rust (no exception-handling blocks) ─────────────────────────────

    def _scan_go(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for assign in find_assignments(content, Lang.GO):
            if assign["target"].strip() == "_":
                value = assign["value"]
                if value and not value.startswith('"') and not value.startswith("'"):
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            line_start=assign["line"],
                            title="Error explicitly discarded with _ =",
                            description=(
                                "Error return value is explicitly discarded. "
                                "Check the error or use a linter to enforce error checking."
                            ),
                            evidence=assign["full_text"][:120],
                            cwe="CWE-755",
                        )
                    )
        return findings

    def _scan_rust(self, content: str, rel_path: str) -> list[Finding]:
        findings: list[Finding] = []
        for call in find_calls(content, Lang.RUST, {"unwrap"}):
            findings.append(
                make_finding(
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    line_start=call["line"],
                    title="Unsafe .unwrap() call",
                    description=(
                        ".unwrap() panics on Err/None. Prefer pattern matching, "
                        "?, or .expect() with a descriptive message."
                    ),
                    evidence=call["full_text"][:120],
                    cwe="CWE-754",
                )
            )
        return findings
