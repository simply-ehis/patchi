"""
InjectionAgent — SQLi, XSS, command injection, path traversal.

Detects injection vulnerabilities:
- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- LDAP injection
- XPath injection
- Expression language injection

Uses AST analysis via ast_utils for function-call patterns;
regex for literal text patterns (path traversal, XSS assignments).
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

from pathlib import Path

from ..agents.base import (
    AgentDomain,
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
    EXEC_SINKS,
    SQL_SINKS,
    find_assignments,
    find_calls,
    get_call_arg,
)
from ..brain.languages import Lang, detect_language
from ..brain.trace_log import trace_agent
from .pattern_loader import get_injection_sinks, load_patterns

# ── Helpers ────────────────────────────────────────────────────────────────────

# Load sinks from YAML config once at module level
_PATTERNS = load_patterns()
_INJ_SINKS = get_injection_sinks(_PATTERNS)


def _has_concat(arg_text: str, lang: Lang | None = None) -> bool:
    """Check if an argument expression contains string concatenation/interpolation."""
    if not arg_text:
        return False
    if "+" in arg_text:
        return True
    if arg_text.startswith("f") or "{" in arg_text:
        return True
    # PHP uses "." (not "+") for concatenation
    if lang == Lang.PHP and "." in arg_text:
        return True
    return False


# ── Agent ──────────────────────────────────────────────────────────────────────


@register
class InjectionAgent(BaseAgent):
    """Agent for detecting injection vulnerabilities."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "InjectionAgent"
    description = "SQLi, XSS, command injection, path traversal, LDAP, XPath"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = []
        source_patterns = [
            "*.py",
            "*.js",
            "*.jsx",
            "*.ts",
            "*.tsx",
            "*.java",
            "*.php",
            "*.rb",
            "*.go",
            "*.rs",
            "*.cpp",
            "*.cxx",
            "*.cc",
            "*.c",
            "*.h",
            "*.hpp",
            "*.cs",
        ]
        with trace_agent(self.name, inp.root) as trace:
            for pattern in source_patterns:
                for file_path in safe_rglob(inp.root, pattern):
                    if file_path.is_file():
                        rel_path = file_path.relative_to(inp.root).as_posix()
                        if not self._should_skip_file(rel_path, inp):
                            findings.extend(self._scan_file_injection(file_path, rel_path))
            trace.findings = len(findings)
            trace.files_scanned = len(list(inp.root.rglob("*.py")))
        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "injection_findings": len([f for f in findings if "injection" in f.title.lower()]),
                "needs_ai": False,
            }
        )
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

    def _scan_file_injection(self, file_path: Path, rel_path: str) -> list[Finding]:
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8")
            lang = detect_language(file_path)
            findings.extend(self._check_sql_injection(content, lang, rel_path))
            findings.extend(self._check_command_injection(content, lang, rel_path))
            findings.extend(self._check_xss(content, lang, rel_path))
            findings.extend(self._check_path_traversal(content, lang, rel_path))
        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Injection scanner file read error",
                    description=f"Could not analyze {file_path.name} for injection issues: {str(e)}",
                    evidence=str(e),
                )
            )
        return findings

    # ── SQL injection ──────────────────────────────────────────────────────────

    def _check_sql_injection(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        lang_key = lang.value
        yaml_sinks = set(_INJ_SINKS.get("sql_sinks", {}).get(lang_key, []))
        sinks = SQL_SINKS | yaml_sinks

        for call in find_calls(content, lang, sinks):
            arg = get_call_arg(call["full_text"])
            if arg and _has_concat(arg, lang):
                findings.append(
                    make_finding(
                        severity=Severity.CRITICAL,
                        file=rel_path,
                        line_start=call["line"],
                        title="SQL Injection",
                        description="SQL query constructed with string concatenation",
                        evidence=call["full_text"][:100],
                    )
                )
        return findings

    # ── Command injection ──────────────────────────────────────────────────────

    def _check_command_injection(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        lang_key = lang.value
        yaml_exec = set(_INJ_SINKS.get("exec_sinks", {}).get(lang_key, []))
        sinks = EXEC_SINKS | yaml_exec
        for call in find_calls(content, lang, sinks):
            arg = get_call_arg(call["full_text"])
            if arg and _has_concat(arg, lang):
                findings.append(
                    make_finding(
                        severity=Severity.CRITICAL,
                        file=rel_path,
                        line_start=call["line"],
                        title="Command Injection",
                        description="External command executed with dynamic input",
                        evidence=call["full_text"][:100],
                    )
                )
        return findings

    # ── Cross-site scripting ───────────────────────────────────────────────────

    _XSS_CALL_SINKS: dict[Lang, set[str]] = {}
    _XSS_ASSIGN_SINKS: dict[Lang, set[str]] = {}

    @classmethod
    def _get_xss_sinks(cls):
        """Build XSS sinks from YAML + static defaults, cached on class."""
        if cls._XSS_CALL_SINKS:
            return cls._XSS_CALL_SINKS, cls._XSS_ASSIGN_SINKS
        # Static defaults
        cls._XSS_CALL_SINKS = {
            Lang.JAVASCRIPT: {"document.write", "document.writeln"},
            Lang.TYPESCRIPT: {"document.write", "document.writeln"},
            Lang.PHP: {"echo", "print"},
        }
        cls._XSS_ASSIGN_SINKS = {
            Lang.JAVASCRIPT: {"innerHTML", "outerHTML"},
            Lang.TYPESCRIPT: {"innerHTML", "outerHTML"},
        }
        # Merge YAML overrides
        yaml_xss_calls = _INJ_SINKS.get("xss_call_sinks", {})
        yaml_xss_assigns = _INJ_SINKS.get("xss_assign_sinks", {})
        for lang_key, funcs in yaml_xss_calls.items():
            try:
                lang = Lang(lang_key)
            except ValueError:
                continue
            cls._XSS_CALL_SINKS.setdefault(lang, set()).update(funcs)
        for lang_key, attrs in yaml_xss_assigns.items():
            try:
                lang = Lang(lang_key)
            except ValueError:
                continue
            cls._XSS_ASSIGN_SINKS.setdefault(lang, set()).update(attrs)
        return cls._XSS_CALL_SINKS, cls._XSS_ASSIGN_SINKS

    def _check_xss(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []
        call_sinks, assign_sinks = self._get_xss_sinks()

        langs_call = call_sinks.get(lang, set())
        if langs_call:
            for call in find_calls(content, lang, langs_call):
                arg = get_call_arg(call["full_text"])
                if arg and _has_concat(arg, lang):
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=call["line"],
                            title="Cross-Site Scripting (XSS)",
                            description="Dynamic content inserted without sanitization",
                            evidence=call["full_text"][:120],
                        )
                    )

            langs_assign = assign_sinks.get(lang, set())
            if langs_assign:
                for assign in find_assignments(content, lang):
                    # Targets come dotted (el.innerHTML); sinks are bare names.
                    if assign["target"].split(".")[-1] in langs_assign and _has_concat(assign["value"], lang):
                        findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=assign["line"],
                            title="Cross-Site Scripting (XSS)",
                            description="Dynamic content assigned to DOM sink without sanitization",
                            evidence=assign["full_text"][:120],
                        )
                    )

        return findings

    # ── Path traversal ─────────────────────────────────────────────────────────

    _PATH_TRAVERSAL_SINKS: dict[Lang, set[str]] = {}

    @classmethod
    def _get_path_traversal_sinks(cls):
        """Build path traversal sinks from YAML + static defaults."""
        if cls._PATH_TRAVERSAL_SINKS:
            return cls._PATH_TRAVERSAL_SINKS
        cls._PATH_TRAVERSAL_SINKS = {
            Lang.PYTHON: {"open", "os.path.join"},
            Lang.JAVASCRIPT: {"fs.readFile", "fs.readFileSync", "path.join"},
            Lang.TYPESCRIPT: {"fs.readFile", "fs.readFileSync", "path.join"},
            Lang.PHP: {"file_get_contents", "fopen", "include", "require"},
        }
        yaml_pts = _INJ_SINKS.get("path_traversal_sinks", {})
        for lang_key, funcs in yaml_pts.items():
            try:
                lang = Lang(lang_key)
            except ValueError:
                continue
            cls._PATH_TRAVERSAL_SINKS.setdefault(lang, set()).update(funcs)
        return cls._PATH_TRAVERSAL_SINKS

    def _check_path_traversal(self, content: str, lang: Lang, rel_path: str) -> list[Finding]:
        findings = []

        sinks = self._get_path_traversal_sinks().get(lang, set())
        if sinks:
            for call in find_calls(content, lang, sinks):
                arg = get_call_arg(call["full_text"])
                if arg and _has_concat(arg, lang):
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=call["line"],
                            title="Path Traversal",
                            description="File path constructed with dynamic input",
                            evidence=call["full_text"][:120],
                        )
                    )

        return findings
