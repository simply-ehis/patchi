"""
Charter — Project Guard Rails.

Lets the user declare what the project *should be* via structured rules:

    p charter set "Frontend must not import backend"
    p charter set "All files must have headers"
    p charter set "No hardcoded secrets"

Rules are stored in ``.patchi/memory/charter.json`` with explicit fields
(no regex/heuristics — structured matching only).

Three enforcement points:
  1. Pre-commit (humans): checks changed files against charter
  2. Watch mode (realtime): flags violations on file save
  3. Governor (agents): charter rules become escalation triggers

Rule types:
  boundary    — forbidden import edges (from -> to)
  convention  — file/line limits, naming, test requirements
  security    — forbidden patterns (secrets, eval, pickle)
  stack       — allowed languages, frameworks
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from patchi.core.config import MEMORY_DIR

_log = logging.getLogger("patchi.charter")

CHARTER_FILE = "charter.json"


class RuleType(StrEnum):
    STACK = "stack"
    BOUNDARY = "boundary"
    CONVENTION = "convention"
    SECURITY = "security"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CharterRule:
    """A single project guard-rail rule with explicit fields."""

    id: str
    type: RuleType
    description: str
    severity: Severity = Severity.MEDIUM
    enabled: bool = True

    # Boundary fields
    from_pattern: str = ""  # source subsystem/path prefix
    to_pattern: str = ""  # target subsystem/path prefix

    # Convention fields
    max_value: int = 0  # max lines/size
    metric: str = ""  # "lines", "file_size", "functions"
    scope: str = ""  # "functions", "classes", "all_files"

    # Security fields
    pattern_type: str = ""  # "forbidden_keywords", "forbidden_imports"
    keywords: list[str] = field(default_factory=list)

    # Stack fields
    allowed_languages: list[str] = field(default_factory=list)
    allowed_frameworks: list[str] = field(default_factory=list)

    # Generic metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "type": self.type.value,
            "description": self.description,
            "severity": self.severity.value,
            "enabled": self.enabled,
        }
        if self.from_pattern:
            d["from_pattern"] = self.from_pattern
        if self.to_pattern:
            d["to_pattern"] = self.to_pattern
        if self.max_value:
            d["max_value"] = self.max_value
        if self.metric:
            d["metric"] = self.metric
        if self.scope:
            d["scope"] = self.scope
        if self.keywords:
            d["keywords"] = self.keywords
        if self.allowed_languages:
            d["allowed_languages"] = self.allowed_languages
        if self.allowed_frameworks:
            d["allowed_frameworks"] = self.allowed_frameworks
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CharterRule:
        return cls(
            id=d["id"],
            type=RuleType(d["type"]),
            description=d.get("description", ""),
            severity=Severity(d.get("severity", "medium")),
            enabled=d.get("enabled", True),
            from_pattern=d.get("from_pattern", ""),
            to_pattern=d.get("to_pattern", ""),
            max_value=d.get("max_value", 0),
            metric=d.get("metric", ""),
            scope=d.get("scope", ""),
            keywords=d.get("keywords", []),
            allowed_languages=d.get("allowed_languages", []),
            allowed_frameworks=d.get("allowed_frameworks", []),
            metadata=d.get("metadata", {}),
        )


@dataclass
class CharterViolation:
    """A detected violation of a charter rule."""

    rule_id: str
    rule_description: str
    severity: str
    file_path: str = ""
    line: int = 0
    message: str = ""
    suggestion: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_description": self.rule_description,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "message": self.message,
            "suggestion": self.suggestion,
        }


@dataclass
class Charter:
    """The full project charter — a collection of guard-rail rules."""

    text: str = ""
    rules: list[CharterRule] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "rules": [r.to_dict() for r in self.rules],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Charter:
        return cls(
            text=d.get("text", ""),
            rules=[CharterRule.from_dict(r) for r in d.get("rules", [])],
            created_at=d.get("created_at", ""),
            updated_at=d.get("updated_at", ""),
        )

    def add_rule(self, text: str) -> CharterRule | None:
        """Add a rule from natural language text using structured parsing."""
        rules = parse_nl_to_rules(text)
        if rules:
            self.rules.extend(rules)
            return rules[0]
        return None

    @classmethod
    def load(cls, root: Path | None = None) -> Charter:
        """Load charter from disk, or return empty."""
        return load_charter(root)


# ── Structured NL Parser (no regex) ─────────────────────────────────────────


def _classify_text(text: str) -> RuleType:
    """Classify natural language text into a rule type using keyword matching."""
    lower = text.lower()

    # Boundary: must/must not/cannot import, never import
    boundary_words = ["must not import", "cannot import", "never import",
                      "should not import", "must not use", "cannot use"]
    if any(w in lower for w in boundary_words):
        return RuleType.BOUNDARY

    # Convention: limits, naming, tests
    convention_words = ["under", "below", "less than", "max", "maximum",
                        "must have", "requires tests", "need tests",
                        "all files must", "every file", "snake_case", "camelCase"]
    if any(w in lower for w in convention_words):
        return RuleType.CONVENTION

    # Security: secrets, eval, pickle
    security_words = ["no secrets", "no hardcoded", "no eval", "no pickle",
                      "no marshal", "no debug", "use https", "parameterized"]
    if any(w in lower for w in security_words):
        return RuleType.SECURITY

    # Stack: languages, frameworks
    stack_words = ["only python", "only javascript", "use go", "use rust",
                   "frameworks allowed", "languages allowed", "stack is"]
    if any(w in lower for w in stack_words):
        return RuleType.STACK

    return RuleType.CONVENTION  # default


def _parse_boundary(text: str) -> CharterRule:
    """Parse a boundary rule from text."""
    lower = text.lower()

    # Extract source and target from "X must not import Y"
    from_pattern = ""
    to_pattern = ""

    # Try to find the pattern: "X must not import Y" or "X cannot import Y"
    for sep in ["must not import", "cannot import", "never import",
                "should not import", "must not use", "cannot use"]:
        if sep in lower:
            parts = lower.split(sep)
            if len(parts) == 2:
                from_pattern = parts[0].strip().rstrip()
                to_pattern = parts[1].strip().lstrip()
                break

    # Clean up extracted patterns
    # Remove leading articles/determiners
    for prefix in ["the ", "a ", "an "]:
        if from_pattern.startswith(prefix):
            from_pattern = from_pattern[len(prefix):]
        if to_pattern.startswith(prefix):
            to_pattern = to_pattern[len(prefix):]

    return CharterRule(
        id="b-001",
        type=RuleType.BOUNDARY,
        description=text,
        severity=Severity.HIGH,
        from_pattern=from_pattern,
        to_pattern=to_pattern,
    )


def _parse_convention(text: str) -> CharterRule:
    """Parse a convention rule from text."""
    lower = text.lower()

    # Extract numeric limits
    max_value = 0
    metric = ""
    scope = ""

    # Try "under N lines" pattern
    if "under" in lower or "below" in lower or "less than" in lower:
        for word in lower.split():
            if word.isdigit():
                max_value = int(word)
                break
        if "lines" in lower:
            metric = "lines"
            # Extract scope
            for s in ["file", "files", "function", "functions",
                      "class", "classes", "service", "services"]:
                if s in lower:
                    scope = s + "s" if not s.endswith("s") else s
                    break

    # Try "must have tests" pattern
    if "must have" in lower or "need" in lower or "require" in lower:
        if "test" in lower:
            scope = "tests_required"

    # Try naming conventions
    if "snake_case" in lower:
        scope = "snake_case"
    elif "camelCase" in lower:
        scope = "camel_case"
    elif "PascalCase" in lower:
        scope = "pascal_case"

    # Try "all files must have X" pattern
    if "all files must" in lower or "every file" in lower:
        if "header" in lower:
            scope = "headers_required"
        elif "docstring" in lower:
            scope = "docstrings_required"

    return CharterRule(
        id="c-001",
        type=RuleType.CONVENTION,
        description=text,
        severity=Severity.MEDIUM,
        max_value=max_value,
        metric=metric,
        scope=scope,
    )


def _parse_security(text: str) -> CharterRule:
    """Parse a security rule from text."""
    lower = text.lower()

    # Extract forbidden keywords
    keywords = []
    if "hardcoded" in lower or "hard coded" in lower:
        keywords.extend(["password", "secret", "api_key", "token"])
    if "eval" in lower:
        keywords.append("eval")
    if "pickle" in lower:
        keywords.append("pickle")
    if "marshal" in lower:
        keywords.append("marshal")
    if "debug" in lower:
        keywords.append("debug")
    if "http" in lower and "https" not in lower:
        keywords.append("http://")
    if "parameterized" in lower:
        keywords.append("raw_sql")

    return CharterRule(
        id="s-001",
        type=RuleType.SECURITY,
        description=text,
        severity=Severity.HIGH if keywords else Severity.MEDIUM,
        pattern_type="forbidden_keywords",
        keywords=keywords,
    )


def _parse_stack(text: str) -> CharterRule:
    """Parse a stack rule from text."""
    lower = text.lower()

    # Extract allowed languages
    allowed_languages = []
    lang_keywords = {
        "python": "python", "javascript": "javascript", "typescript": "typescript",
        "go": "go", "rust": "rust", "java": "java", "c#": "csharp",
    }
    for kw, lang in lang_keywords.items():
        if kw in lower:
            allowed_languages.append(lang)

    return CharterRule(
        id="t-001",
        type=RuleType.STACK,
        description=text,
        severity=Severity.MEDIUM,
        allowed_languages=allowed_languages,
    )


def parse_nl_to_rules(text: str) -> list[CharterRule]:
    """Parse natural language into structured rules (no regex, no heuristics).

    Uses keyword matching to classify text into rule types, then extracts
    explicit fields for each rule type.
    """
    rules = []
    rule_type = _classify_text(text)

    if rule_type == RuleType.BOUNDARY:
        rules.append(_parse_boundary(text))
    elif rule_type == RuleType.CONVENTION:
        rules.append(_parse_convention(text))
    elif rule_type == RuleType.SECURITY:
        rules.append(_parse_security(text))
    elif rule_type == RuleType.STACK:
        rules.append(_parse_stack(text))

    return rules


# ── Rule Checking (structured matching) ──────────────────────────────────────


def check_boundary_violations(
    charter: Charter,
    import_edges: list[tuple[str, str]],
) -> list[CharterViolation]:
    """Check if import edges violate boundary rules using structured matching."""
    violations: list[CharterViolation] = []
    boundary_rules = [r for r in charter.rules
                      if r.type == RuleType.BOUNDARY and r.enabled]

    for rule in boundary_rules:
        from_pat = rule.from_pattern.lower()
        to_pat = rule.to_pattern.lower()

        if not from_pat or not to_pat:
            continue

        for src, dst in import_edges:
            # Check if source matches from_pattern and target matches to_pattern
            src_lower = src.lower()
            dst_lower = dst.lower()

            # Match using prefix matching (structured, not regex)
            if from_pat in src_lower and to_pat in dst_lower:
                violations.append(CharterViolation(
                    rule_id=rule.id,
                    rule_description=rule.description,
                    severity=rule.severity.value,
                    file_path=src,
                    message=f"'{src}' imports '{dst}' — violates boundary rule",
                    suggestion=f"Remove import of {to_pat} from {from_pat}",
                ))

    return violations


def check_convention_violations(
    charter: Charter,
    file_infos: list[Any],
) -> list[CharterViolation]:
    """Check files against convention rules using structured matching."""
    violations: list[CharterViolation] = []
    conv_rules = [r for r in charter.rules
                  if r.type == RuleType.CONVENTION and r.enabled]

    for rule in conv_rules:
        if rule.max_value > 0 and rule.metric == "lines":
            for fi in file_infos:
                path = getattr(fi, "path", "")
                if path.endswith((".py", ".ts", ".js", ".go", ".java", ".rs")):
                    line_count = getattr(fi, "line_count", 0)
                    if line_count and line_count > rule.max_value:
                        violations.append(CharterViolation(
                            rule_id=rule.id,
                            rule_description=rule.description,
                            severity=rule.severity.value,
                            file_path=path,
                            message=f"{path} is {line_count} lines (max {rule.max_value})",
                            suggestion=f"Split into modules under {rule.max_value} lines",
                        ))

    return violations


def check_all_violations(
    charter: Charter,
    import_edges: list[tuple[str, str]] | None = None,
    file_infos: list[Any] | None = None,
) -> list[CharterViolation]:
    """Run all charter checks and return combined violations."""
    violations: list[CharterViolation] = []

    if import_edges:
        violations.extend(check_boundary_violations(charter, import_edges))

    if file_infos:
        violations.extend(check_convention_violations(charter, file_infos))

    return violations


# ── Persistence ───────────────────────────────────────────────────────────────


def _charter_path(root: Path | None = None) -> Path:
    r = root or Path.cwd()
    return r / MEMORY_DIR / CHARTER_FILE


def load_charter(root: Path | None = None) -> Charter:
    """Load charter from disk, or return empty."""
    path = _charter_path(root)
    if not path.exists():
        return Charter()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return Charter.from_dict(data)
    except Exception:
        _log.warning("Failed to load charter from %s", path)
        return Charter()


def save_charter(charter: Charter, root: Path | None = None) -> Path:
    """Save charter to disk."""
    path = _charter_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(charter.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path
