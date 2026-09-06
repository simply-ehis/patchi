"""
Agent base class and shared result types for Patchi.

Every agent in the system — scanner, fix, test, security, guard — inherits
from BaseAgent and returns an AgentResult. No agent ever:
  - Writes files directly (only fix agents propose patches; the queue applies them)
  - Calls AI when static analysis is sufficient
  - Runs outside its declared scope

Agent contract:
  1. Receive AgentInput (project root, target scope, brain data, config)
  2. Do work (static analysis / AST parse / subprocess / http request)
  3. Return AgentResult (findings, metadata, duration, errors)
  4. Done. Never mutate state. Never touch the queue directly.
"""
from __future__ import annotations

import ast
import fnmatch
import logging
import os
import time
import traceback
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from patchi.core.brain.file_corpus import FileCorpus
from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS, is_minified_asset

# ponytail: rglob traverses node_modules (30k+ files). Shared skip sets.
_SKIP_DIRS = frozenset(DEFAULT_IGNORE_DIRS)
_SKIP_FILES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock", "Gemfile.lock"}
)


def _skip_asset(fname: str, skip_files: frozenset[str]) -> bool:
    """True when a filename is user-skipped or a minified/bundled asset."""
    return fname in skip_files or is_minified_asset(fname)


def scope_allows(inp: AgentInput, rel_path: str) -> bool:
    """True when `rel_path` is inside the agent's target scope.

    Empty scope means whole-tree (unchanged behavior). Entries match as
    exact files or directory prefixes, so per-file sharding and --since
    scoping work without touching every agent's walk logic.
    """
    scope = inp.scope or []
    if not scope:
        return True
    rel = rel_path.replace("\\", "/").lstrip("./")
    for entry in scope:
        e = str(entry).replace("\\", "/").lstrip("./")
        if rel == e or rel.startswith(e.rstrip("/") + "/"):
            return True
    return False


_log = logging.getLogger("patchi.agents.base")


def safe_rglob(
    root: Path,
    pattern: str,
    skip_files: frozenset[str] = frozenset(),
    corpus: FileCorpus | None = None,
):
    """Yield Path objects matching `pattern` without entering node_modules etc.

    When `corpus` is provided, uses the pre-built FileCorpus index instead of
    walking the filesystem — avoids redundant directory traversal across
    the 60+ callers that each independently walk the tree.
    """
    if corpus is not None:
        for entry in corpus.by_glob(pattern):
            if _skip_asset(entry.path, skip_files) or _skip_asset(
                Path(entry.path).name, skip_files
            ):
                continue
            yield root / entry.path
        return

    if "/" not in pattern and "**" not in pattern:
        # Simple pattern like "*.py" — walk with pruning
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if _skip_asset(fname, skip_files):
                    continue
                if fnmatch.fnmatch(fname, pattern):
                    yield Path(dirpath) / fname
    elif "**" in pattern:
        # Compound pattern like "**/routes/**" — split and match
        parts = pattern.split("/")
        mid = parts[1] if len(parts) > 2 else None
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            rel = Path(dirpath).relative_to(root).as_posix()
            if mid and mid not in rel.split("/"):
                continue
            for fname in filenames:
                if _skip_asset(fname, skip_files):
                    continue
                if fnmatch.fnmatch(fname, parts[-1]):
                    yield Path(dirpath) / fname
    else:
        # Compound pattern like ".github/workflows/*" — walk, match dir+filename
        parts = pattern.rsplit("/", 1)
        dir_part = parts[0] if len(parts) > 1 else ""
        file_part = parts[-1]
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            rel = Path(dirpath).relative_to(root).as_posix()
            if dir_part and dir_part not in rel:
                continue
            for fname in filenames:
                if _skip_asset(fname, skip_files):
                    continue
                if fnmatch.fnmatch(fname, file_part):
                    yield Path(dirpath) / fname


# ── Agent groups ───────────────────────────────────────────────────────────────


class AgentGroup(StrEnum):
    SCANNER = "scanner"
    FIX = "fix"
    TEST = "test"
    SECURITY = "security"
    GUARD = "guard"

    def label(self) -> str:
        labels = {
            "scanner": "Scanner Agents",
            "fix": "Fix Agents",
            "test": "Test Agents",
            "security": "Security Agents",
            "guard": "Guard Agents",
        }
        return labels[self.value]

    def ant_type(self) -> str:
        """Which ant type represents this group in the web UI colony."""
        return {
            "scanner": "minor_worker",
            "fix": "minor_worker",
            "test": "minor_worker",
            "security": "soldier",
            "guard": "soldier",
        }[self.value]


# ── Agent status ───────────────────────────────────────────────────────────────


class AgentStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    SUCCEEDED = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


# ── Severity levels (used across all finding types) ────────────────────────────


class Severity(StrEnum):
    CRITICAL = "critical"  # level 1 alert
    HIGH = "high"  # level 2 alert
    MEDIUM = "medium"  # level 3 alert
    LOW = "low"  # level 4, digest only
    INFO = "info"  # never alerts, informational only

    def color(self) -> str:
        return {
            "critical": "#FF4D6D",
            "high": "#FF8C42",
            "medium": "#FACC15",
            "low": "#4ADE80",
            "info": "#B8A898",
        }[self.value]

    def sort_key(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[self.value]


# ── Finding — universal result item ───────────────────────────────────────────


@dataclass
class Finding:
    """
    A single finding from any agent.
    Used by scanner, security, and guard agents.
    Fix agents produce Patch objects , not findings.
    """

    agent: str  # agent name that produced this
    type: str  # e.g. "dead_code", "missing_type", "todo_comment"
    severity: Severity
    file: str  # relative path to project root
    line: int = 0  # line number (0 = file-level finding)
    column: int = 0
    message: str = ""  # one sentence, human readable
    detail: str = ""  # full context, multi-line
    code_snippet: str = ""  # the relevant code, never secret values
    suggestion: str = ""  # what to do about it (no code — that's fix agents)
    fix_agent: str | None = None  # which fix agent handles this
    cwe: str = ""  # CWE reference if applicable
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "type": self.type,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "detail": self.detail,
            "code_snippet": self.code_snippet,
            "suggestion": self.suggestion,
            "fix_agent": self.fix_agent,
            "cwe": self.cwe,
            **self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        extra_keys = {
            "agent",
            "type",
            "severity",
            "file",
            "line",
            "column",
            "message",
            "detail",
            "code_snippet",
            "suggestion",
            "fix_agent",
            "cwe",
        }
        extra = {k: v for k, v in d.items() if k not in extra_keys}
        return cls(
            agent=d.get("agent", ""),
            type=d.get("type", ""),
            severity=Severity(d.get("severity", "medium")),
            file=d.get("file", ""),
            line=d.get("line", 0),
            column=d.get("column", 0),
            message=d.get("message", ""),
            detail=d.get("detail", ""),
            code_snippet=d.get("code_snippet", ""),
            suggestion=d.get("suggestion", ""),
            fix_agent=d.get("fix_agent"),
            cwe=d.get("cwe", ""),
            extra=extra,
        )

    @property
    def title(self) -> str:
        """Legacy alias for finding message/title compatibility."""
        return self.message

    @title.setter
    def title(self, value: str) -> None:
        self.message = value


# ── Agent input ────────────────────────────────────────────────────────────────


@dataclass
class AgentInput:
    """
    Standard input passed to every agent's run() method.

    Agents must not read config or brain directly — everything
    they need is injected here. This keeps agents testable in isolation.
    """

    root: Path  # project root
    scope: list[str]  # relative file paths to analyse (empty = all)
    brain: dict  # current brain state (from memory.get_brain())
    config: dict  # current config (from config.load())
    extra: dict = field(default_factory=dict)  # agent-specific params
    purpose: str = ""  # project purpose (from brain scan, e.g. "A AI CLI for code scanning")
    domain: str = ""  # project domain (e.g. "dev-tool", "web-app", "library")
    context: dict = field(default_factory=dict)  # rich project context from brain context phase
    active_domains: list[str] = field(default_factory=list)  # activated security domain IDs
    on_message: callable | None = (
        None  # callback for live progress streaming: fn(agent_name, message, style)
    )
    on_ai_progress: callable | None = (
        None  # callback for AI call progress: fn(message)
    )


# ── Agent result ───────────────────────────────────────────────────────────────


@dataclass
class AgentResult:
    """
    Standard output from every agent's run() method.
    """

    agent_name: str = ""
    agent_group: AgentGroup = AgentGroup.SCANNER
    status: AgentStatus = AgentStatus.IDLE
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    metadata: dict | None = None

    findings: list[Finding] = field(default_factory=list)
    data: dict = field(default_factory=dict)  # structured output beyond findings
    errors: list[str] = field(default_factory=list)
    files_scanned: int = 0
    ai_calls_made: int = 0  # track AI usage for cost awareness

    def __post_init__(self) -> None:
        if self.metadata is not None:
            self.data.update(self.metadata)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(error)
        self.status = AgentStatus.FAILED

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result

    def to_dict(self) -> dict:
        return {
            "agent": self.agent_name,
            "group": self.agent_group.value,
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "files_scanned": self.files_scanned,
            "ai_calls_made": self.ai_calls_made,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, d: dict) -> AgentResult:
        return cls(
            agent_name=d.get("agent", ""),
            agent_group=AgentGroup(d.get("group", "scanner")),
            status=AgentStatus(d.get("status", "idle")),
            started_at=d.get("started_at", ""),
            completed_at=d.get("completed_at", ""),
            duration_ms=d.get("duration_ms", 0),
            files_scanned=d.get("files_scanned", 0),
            ai_calls_made=d.get("ai_calls_made", 0),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            data=d.get("data", {}),
            errors=d.get("errors", []),
        )

    def summary_line(self) -> str:
        status_icon = {
            AgentStatus.DONE: "✓",
            AgentStatus.FAILED: "✗",
            AgentStatus.SKIPPED: "○",
            AgentStatus.RUNNING: "↻",
            AgentStatus.IDLE: "·",
        }[self.status]
        findings_str = f"{self.finding_count} findings" if self.finding_count else "no findings"
        return f"{status_icon} {self.agent_name:<24} {findings_str:<18} {self.duration_ms}ms"


# ── Skills directory (companion .skill.md files for security/review agents) ─────

_SKILLS_DIR: Path | None = None


def _get_skills_dir() -> Path | None:
    global _SKILLS_DIR
    if _SKILLS_DIR is not None:
        return _SKILLS_DIR
    candidate = Path(__file__).resolve().parent.parent / "security" / "skills"
    _SKILLS_DIR = candidate if candidate.is_dir() else None
    return _SKILLS_DIR


_SKILL_CACHE: dict[str, dict[str, str]] | None = None
"""Global cache: agent_name -> {skill_stem -> skill_content}. Populated once."""


def _build_skill_map() -> dict[str, dict[str, str]]:
    """Scan skills_dir, parse target_agents frontmatter, return reverse map."""
    global _SKILL_CACHE
    if _SKILL_CACHE is not None:
        return _SKILL_CACHE
    skills_dir = _get_skills_dir()
    if not skills_dir:
        _SKILL_CACHE = {}
        return _SKILL_CACHE

    import re

    agent_skills: dict[str, dict[str, str]] = {}
    for f in sorted(skills_dir.glob("*.skill.md")):
        content = f.read_text(encoding="utf-8")
        stem = f.stem
        # Extract target_agents from YAML frontmatter (between --- markers)
        m = re.search(r"(?m)^target_agents:\s*\[([^\]]+)\]", content)
        if not m:
            m = re.search(r"(?m)^target_agents:\s*(.+?)$", content)
        if m:
            raw = m.group(1)
            names = [n.strip().strip("'\"") for n in raw.split(",") if n.strip()]
            for name in names:
                agent_skills.setdefault(name, {})[stem] = content
    _SKILL_CACHE = agent_skills
    return agent_skills


# ── Base agent ─────────────────────────────────────────────────────────────────


class BaseAgent(ABC):
    """
    Abstract base for all Patchi agents.

    Subclasses implement _run() with their analysis logic.
    run() wraps _run() with timing, error handling, and result finalization.

    Agents must:
    - Be stateless between calls (all state lives in AgentInput/AgentResult)
    - Return within their declared timeout
    - Never write to disk
    - Never modify the queue or brain directly
    """

    # Override these in subclasses
    name: str = "BaseAgent"
    group: AgentGroup = AgentGroup.SCANNER
    timeout: int = 60  # seconds — coordinator enforces this

    def run(self, inp: AgentInput) -> AgentResult:
        """
        Public entry point. Wraps _run() with timing, error handling,
        and companion skill loading.

        Companion skill files (.skill.md) from patchi/core/security/skills/
        are auto-discovered based on self.name appearing in the file's
        target_agents frontmatter.  Loaded content is available as:

            inp.extra.get("skill_context", {})     — dict of {skill_stem: content}
            getattr(self, "_skill_context", {})     — same, on the agent instance

        Never override this — override _run() instead.
        """
        # Gate Rule — Testing/Live/Attack must confirm P-Check READY_TO_SERVE
        if self.group in (AgentGroup.TEST, AgentGroup.SECURITY) and self.name not in ("PreCheckAgent",):
            # Only gate live/test/attack agents, not pure static scanners
            needs_gate = self.group == AgentGroup.TEST or self.name in (
                "RedTeamAgent",
                "RedTeamEngineAgent",
                "DastAgent",
                "BrowserTestAgent",
                "UIButtonAgent",
                "UILayoutAgent",
                "UIAccessibilityAgent",
                "VisualRegressionAgent",
                "E2EFlowAgent",
                "ApiFuzzerAgent",
                "StressTestAgent",
            )
            if needs_gate:
                try:
                    from patchi.core.testing.gate import require_ready

                    ready, url, st = require_ready(inp.root)
                    if not ready:
                        from patchi.core.testing.gate import gate_message

                        msg = gate_message(st)
                        # Stay idle — do not run, request P-Check
                        result = AgentResult(
                            agent_name=self.name,
                            agent_group=self.group,
                            status=AgentStatus.SKIPPED,
                        )
                        result.data["gate_blocked"] = True
                        result.data["gate_reason"] = msg
                        result.data["gate_status"] = st
                        result.errors.append(msg)
                        return result
                    # Inject url for agents that need it
                    if url and not inp.extra.get("base_url"):
                        safe_extra = dict(inp.extra)
                        safe_extra["base_url"] = url
                        safe_extra["live_probe"] = True
                except Exception as e:
                    _log.debug("gate check failed: %s", e)

        # Load companion skills for this agent name
        skill_map = _build_skill_map()
        self._skill_context = skill_map.get(self.name, {})
        # Inject into inp.extra with a unique key to avoid cross-agent interference
        # when multiple agents share the same AgentInput object in parallel runs.
        safe_extra = dict(inp.extra)
        safe_extra["skill_context"] = self._skill_context
        inp = AgentInput(
            root=inp.root,
            scope=inp.scope,
            brain=inp.brain,
            config=inp.config,
            extra=safe_extra,
            on_message=getattr(inp, "on_message", None),
            domain=getattr(inp, "domain", ""),
            purpose=getattr(inp, "purpose", ""),
            context=getattr(inp, "context", {}),
            active_domains=getattr(inp, "active_domains", None),
        )

        result = AgentResult(
            agent_name=self.name,
            agent_group=self.group,
            status=AgentStatus.RUNNING,
            started_at=_now(),
        )

        t0 = time.monotonic()
        try:
            # Every registered agent implements _run(inp, result) -> None
            # (enforced by register()/validate_agent_registry()); the old
            # inspect.signature shim for _run(inp) -> AgentResult is gone.
            self._run(inp, result)
            if result.status == AgentStatus.RUNNING:
                result.status = AgentStatus.DONE
        except Exception as e:
            result.errors.append(f"{type(e).__name__}: {e}")
            result.errors.append(traceback.format_exc())
            result.status = AgentStatus.FAILED

        result.completed_at = _now()
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    @abstractmethod
    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """
        Implement analysis logic here.
        Append findings to result.findings.
        Write structured data to result.data.
        Call result.add_error() on non-fatal errors.
        Raise exceptions for fatal errors (they are caught by run()).
        """
        ...

    def skip(self, result: AgentResult, reason: str) -> None:
        """Mark agent as skipped with a reason."""
        result.status = AgentStatus.SKIPPED
        result.data["skip_reason"] = reason

    @classmethod
    def describe(cls) -> dict:
        """Return metadata for `p agents list`."""
        return {
            "name": cls.name,
            "group": cls.group.value,
            "timeout": cls.timeout,
        }  # ── Registry ───────────────────────────────────────────────────────────────────


_REGISTRY: dict[str, type[BaseAgent]] = {}

# Packages walked by discover_agent_modules() so every @register side-effect
# fires. Mirrors where agents live across the codebase; a module added here
# without being imported by an aggregator (scanners.py, security_agents.py,
# test_agents.py, fix/__init__.py) still gets discovered.
AGENT_PACKAGES: tuple[str, ...] = (
    "patchi.core.agents",
    "patchi.core.security",
    "patchi.core.testing",
    "patchi.core.fix",
    "patchi.core.detector",
)


def discover_agent_modules(packages: tuple[str, ...] = AGENT_PACKAGES) -> list[str]:
    """Import every module under the agent packages so @register fires.

    Replaces hand-maintained aggregator import lists (the sweep previously
    enumerated 10 modules by hand; a new agent module nobody imported was
    silently invisible). Walks each package with pkgutil and imports every
    submodule, tolerating import failures: returns formatted failure strings
    ("module -> ErrorType: message") for every module that FAILED to import
    (empty = everything imported cleanly).

    NOTE: modules with heavy optional deps (playwright, torch, pyre) are
    imported lazily by their agent bodies, so discovery stays cheap.
    """
    import importlib
    import pkgutil

    failures: list[str] = []
    for pkg_name in packages:
        try:
            pkg = importlib.import_module(pkg_name)
        except Exception as e:  # noqa: BLE001 — report and continue
            failures.append(f"{pkg_name} -> {type(e).__name__}: {e}")
            continue
        pkg_path = getattr(pkg, "__path__", [])
        for mod_info in pkgutil.iter_modules(pkg_path, prefix=pkg_name + "."):
            if mod_info.ispkg:
                # Import sub-packages (e.g. security sub-folders) too.
                for sub_fail in discover_agent_modules((mod_info.name,)):
                    failures.append(sub_fail)
                continue
            try:
                importlib.import_module(mod_info.name)
            except Exception as e:  # noqa: BLE001 — report and continue
                failures.append(f"{mod_info.name} -> {type(e).__name__}: {e}")
    return failures


def validate_agent_registry() -> list[str]:
    """Startup contract check over every registered agent.

    Returns a list of violation strings (empty = all agents satisfy the
    contract). Catches the audit's registration bug classes AT IMPORT TIME
    instead of in the sweep or mid-pipeline:

      * a @register-ed plain class that is not a BaseAgent subclass
        (PysaAgent/CodeqlAgent had no run() and no AgentResult)
      * a class whose body raised while reading AgentGroup (e.g. referencing
        a nonexistent AgentGroup member, so it silently never registered)
      * an agent without a name, or with a group outside AgentGroup

    Call after discover_agent_modules() (or after any aggregator import).
    """
    # Note: this is defense-in-depth — strict register() already guarantees the
    # contract for anything added through the decorator, so this only fires for
    # entries injected directly into _REGISTRY. Kept as the startup audit the
    # sweep runs, per the deep-audit requirement.
    violations: list[str] = []
    for name, cls in _REGISTRY.items():
        if not (isinstance(cls, type) and issubclass(cls, BaseAgent)):
            violations.append(
                f"{name}: registered class is not a BaseAgent subclass "
                f"(no run()/AgentResult contract)"
            )
            continue
        if not callable(getattr(cls, "run", None)):
            violations.append(f"{name}: registered agent has no callable run()")
        agent_name = getattr(cls, "name", "")
        if not agent_name or not isinstance(agent_name, str) or agent_name == "BaseAgent":
            violations.append(f"{name}: agent has no usable .name (inherited BaseAgent default)")
        group = getattr(cls, "group", None)
        if not isinstance(group, AgentGroup):
            violations.append(f"{name}: group {group!r} is not an AgentGroup member")
        try:
            _check_run_signature(cls)
        except TypeError as e:
            violations.append(str(e))
        # _run(inp, result) mutates the passed-in result; any rebinding of the
        # `result` name (for-loop target, comprehension target, plain assign)
        # that is followed by a LATER use of `result` silently discards the
        # AgentResult and crashes (AttributeError: 'dict' object has no
        # attribute 'status' — the accessibility/api-contract shadow bugs).
        for lineno, kind in _find_result_shadowing(cls):
            violations.append(
                f"{name}: _run rebinds `result` at line {lineno} "
                f"({kind}) and uses it afterwards — rename the loop variable"
            )
    return violations


def _iter_target_names(node) -> list[str]:
    """All assigned names under an assign/for/comprehension target, recursing
    through tuple/list/starred unpacking."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in node.elts:
            out.extend(_iter_target_names(elt))
        return out
    if isinstance(node, ast.Starred):
        return _iter_target_names(node.value)
    return []


def _find_result_shadowing(cls: type) -> list[tuple[int, str]]:
    """Return [(lineno, kind)] where `_run` rebinds `result` and then uses it
    again later — the passed-in AgentResult would be lost.

    A rebind with NO later use is intentionally not flagged (harmless, e.g. a
    trailing loop that iterates dicts and returns). Rebinds are detected at
    the statement level; a load on the SAME line (e.g. `result.get(...)`
    inside the comprehension that rebinds it) refers to the new binding and is
    correct, so only loads on strictly later lines trigger a violation.
    """
    # Read source directly from the file to avoid inspect.getsource()
    # deadlocks on Windows when pytest-timeout threads conflict.
    try:
        import sys as _sys
        mod_name = cls.__module__
        mod = _sys.modules.get(mod_name)
        if mod and hasattr(mod, '__file__') and mod.__file__:
            src_path = Path(mod.__file__)
            if src_path.suffix == '.pyc' and src_path.with_suffix('.py').exists():
                src_path = src_path.with_suffix('.py')
            if src_path.exists():
                src = src_path.read_text(encoding='utf-8', errors='replace')
            else:
                return []
        else:
            return []
    except Exception:
        return []
    try:
        tree = ast.parse(src)
    except (SyntaxError, IndentationError):
        return []
    # Find the class node matching cls.__name__, then its _run method
    run_fn = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            if isinstance(node, ast.ClassDef) and node.name == cls.__name__:
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name == "_run":
                        if "result" in [a.arg for a in item.args.args]:
                            run_fn = item
                            break
                if run_fn:
                    break
    if run_fn is None:
        return []

    rebinds: dict[int, str] = {}  # lineno -> kind
    load_lines: set[int] = set()

    for node in ast.walk(run_fn):
        if isinstance(node, ast.For):
            for n in _iter_target_names(node.target):
                if n == "result":
                    rebinds[node.lineno] = "for-loop target"
        elif isinstance(node, ast.comprehension):
            for n in _iter_target_names(node.target):
                if n == "result":
                    rebinds[node.target.lineno] = "comprehension target"
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.NamedExpr)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for n in _iter_target_names(t):
                    if n == "result":
                        rebinds[node.lineno] = "plain assignment"
        elif isinstance(node, ast.Name) and node.id == "result" and isinstance(node.ctx, ast.Load):
            load_lines.add(node.lineno)

    return sorted(
        (line, kind) for line, kind in rebinds.items() if any(load > line for load in load_lines)
    )


def register(agent_cls: type[BaseAgent]) -> type[BaseAgent]:
    """Decorator to register an agent class by name.

    Enforces the agent contract at registration time: the decorated object
    must be a BaseAgent subclass with a name and a real AgentGroup. A plain
    class decorated with @register (the PysaAgent/CodeqlAgent bug) raises
    immediately instead of registering a broken entry.
    """
    if not (isinstance(agent_cls, type) and issubclass(agent_cls, BaseAgent)):
        raise TypeError(
            f"register() requires a BaseAgent subclass, got {agent_cls!r} — "
            "agents must inherit BaseAgent to expose run()/AgentResult"
        )
    if not callable(getattr(agent_cls, "run", None)):
        raise TypeError(f"register() requires {agent_cls.__name__} to expose a callable run()")
    # An agent that never sets .name inherits "BaseAgent" from the base class
    # and would silently OVERWRITE the base entry in the registry — reject the
    # inherited default, not just the empty string.
    agent_name = getattr(agent_cls, "name", "") or ""
    if not agent_name or not isinstance(agent_name, str) or agent_name == "BaseAgent":
        raise TypeError(
            f"register() requires agent {agent_cls.__name__} to define its own .name "
            f"(inherited the BaseAgent default)"
        )
    if not isinstance(getattr(agent_cls, "group", None), AgentGroup):
        raise TypeError(
            f"register() requires {agent_cls.__name__}.group to be an AgentGroup member"
        )
    # The _run contract: every agent must implement _run(self, inp, result)
    # -> None. The old per-call inspect.signature shim in run() was removed, so
    # a wrong-shaped _run would only explode mid-pipeline — catch it here at
    # registration time instead (enforced, not probed).
    _check_run_signature(agent_cls)
    _REGISTRY[agent_cls.name] = agent_cls
    return agent_cls


def _check_run_signature(agent_cls: type[BaseAgent]) -> None:
    """Raise TypeError unless _run takes exactly (self, inp, result)."""
    import inspect

    run_impl = getattr(agent_cls, "_run", None)
    if not callable(run_impl):
        raise TypeError(f"register() requires {agent_cls.__name__} to implement _run()")
    try:
        sig = inspect.signature(run_impl)
    except (TypeError, ValueError) as e:  # noqa: BLE001 — signature probe failure
        raise TypeError(f"register() could not inspect {agent_cls.__name__}._run: {e}") from e
    params = list(sig.parameters.values())
    positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    if len(positional) < 3 or positional[1].name != "inp" or positional[2].name != "result":
        raise TypeError(
            f"register() requires {agent_cls.__name__}._run(self, inp, result) — "
            f"got {sig}. The old _run(inp) -> AgentResult shape is removed."
        )


def deregister(agent_cls: type[BaseAgent]) -> None:
    """Remove an agent class from the registry (for test cleanup)."""
    _REGISTRY.pop(agent_cls.name, None)


def get_agent(name: str) -> type[BaseAgent] | None:
    return _REGISTRY.get(name)


def list_agents(group: AgentGroup | None = None) -> list[type[BaseAgent]]:
    agents = list(_REGISTRY.values())
    if group:
        agents = [a for a in agents if a.group == group]
    return sorted(agents, key=lambda a: (a.group.value, a.name))


# ── Utilities ──────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _infer_agent_name() -> str:
    """Try to infer the calling agent name for legacy make_finding calls."""
    import inspect

    frame = inspect.currentframe()
    if not frame:
        return "Unknown"

    caller = frame.f_back
    while caller:
        self_obj = caller.f_locals.get("self")
        if self_obj is not None:
            agent_name = getattr(self_obj, "name", None)
            if isinstance(agent_name, str) and agent_name:
                return agent_name
        caller = caller.f_back

    return "Unknown"


def make_finding(
    *args,
    **kwargs,
) -> Finding:
    """Create a Finding with backwards compatibility for old call signatures."""
    # Legacy positional form: (Severity, file, line_start, title, description, evidence)
    if args and isinstance(args[0], Severity):
        severity = args[0]
        file = args[1] if len(args) > 1 else ""
        line = args[2] if len(args) > 2 else 0
        title = args[3] if len(args) > 3 else ""
        description = args[4] if len(args) > 4 else ""
        evidence = args[5] if len(args) > 5 else ""
        finding_type = kwargs.pop("finding_type", None) or title.lower().replace(" ", "_").replace(
            ":", ""
        ).replace("'", "").replace("-", "_")
        agent = kwargs.pop("agent", _infer_agent_name())
        message = kwargs.pop("message", "") or title or description
        detail = kwargs.pop("detail", description or evidence)
        return Finding(
            agent=agent,
            type=finding_type,
            severity=severity,
            file=file,
            line=line,
            message=message,
            detail=detail,
            code_snippet=kwargs.pop("code_snippet", ""),
            suggestion=kwargs.pop("suggestion", ""),
            fix_agent=kwargs.pop("fix_agent", None),
            cwe=kwargs.pop("cwe", ""),
            extra={**kwargs},
        )

    # Legacy keyword form: severity=..., file=..., title=..., description=..., evidence=...
    if "severity" in kwargs and ("file" in kwargs or "file_path" in kwargs):
        severity = kwargs.pop("severity")
        file = kwargs.pop("file", kwargs.pop("file_path", ""))
        line = kwargs.pop("line_start", kwargs.pop("line", 0))
        title = kwargs.pop("title", "")
        description = kwargs.pop("description", "")
        message = kwargs.pop("message", "") or title or description
        evidence = kwargs.pop("evidence", "")
        finding_type = kwargs.pop("finding_type", None) or title.lower().replace(" ", "_").replace(
            ":", ""
        ).replace("'", "").replace("-", "_")
        agent = kwargs.pop("agent", _infer_agent_name())
        detail = kwargs.pop("detail", description or evidence)
        return Finding(
            agent=agent,
            type=finding_type,
            severity=severity,
            file=file,
            line=line,
            message=message,
            detail=detail,
            code_snippet=kwargs.pop("code_snippet", ""),
            suggestion=kwargs.pop("suggestion", ""),
            fix_agent=kwargs.pop("fix_agent", None),
            cwe=kwargs.pop("cwe", ""),
            extra={**kwargs},
        )

    # Standard constructor: (agent, finding_type, severity, file, message, ...)
    if len(args) >= 5 and isinstance(args[2], Severity):
        agent = args[0]
        finding_type = args[1]
        severity = args[2]
        file = args[3]
        message = args[4]
        line = kwargs.pop("line", kwargs.pop("line_start", 0))
        evidence = kwargs.pop("evidence", "")  # Extract evidence if passed
        detail = kwargs.pop("detail", evidence)  # Map evidence to detail
        return Finding(
            agent=agent,
            type=finding_type,
            severity=severity,
            file=file,
            line=line,
            message=message,
            detail=detail,
            code_snippet=kwargs.pop("code_snippet", ""),
            suggestion=kwargs.pop("suggestion", ""),
            fix_agent=kwargs.pop("fix_agent", None),
            cwe=kwargs.pop("cwe", ""),
            extra={**kwargs},
        )

    raise TypeError("Invalid make_finding signature")
