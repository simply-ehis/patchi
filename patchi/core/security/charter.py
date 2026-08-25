"""
Charter — Project Guard Rails.

Lets the user declare what the project *should be* via natural language:

    p charter "This is a Flask+React monorepo. Frontend must never import
    backend DB modules. All API routes need tests. No hardcoded secrets.
    Services under 80 lines."

Parsed into structured rules and stored in ``.patchi/charter.json``.

Three enforcement points:
  1. Pre-commit (humans): checks changed files against charter
  2. Watch mode (realtime): flags violations on file save
  3. Governor (agents): charter rules become escalation triggers

Rule types:
  stack       — languages, frameworks, allowed dependencies
  boundary    — forbidden import edges (e.g. "ui imports data")
  convention  — naming, max file/function size, required patterns
  security    — no hardcoded secrets, no pickle/eval, parameterized queries
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from patchi.core.config import MEMORY_DIR

_log = logging.getLogger("patchi.charter")

CHARTER_FILE = "charter.json"

# ── Rule types ───────────────────────────────────────────────────────────────


class RuleType(str, Enum):
    STACK = "stack"
    BOUNDARY = "boundary"
    CONVENTION = "convention"
    SECURITY = "security"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class CharterRule:
    """A single project guard-rail rule."""

    id: str  # e.g. "stack-001", "boundary-003"
    type: RuleType
    description: str  # human-readable rule text
    severity: Severity = Severity.MEDIUM
    # Type-specific fields:
    # stack: allowed languages, frameworks, deps
    # boundary: source_subsystem, target_subsystem, forbidden
    # convention: metric, max_value, applies_to
    # security: pattern, applies_to, action
    metadata: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "id": self.id,
            "type": self.type.value,
            "description": self.description,
            "severity": self.severity.value,
            "metadata": self.metadata,
            "enabled": self.enabled,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CharterRule:
        return cls(
            id=d["id"],
            type=RuleType(d["type"]),
            description=d.get("description", ""),
            severity=Severity(d.get("severity", "medium")),
            metadata=d.get("metadata", {}),
            enabled=d.get("enabled", True),
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

    text: str = ""  # original NL input
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


# ── NL → Rules parser (heuristic, no AI tokens needed) ──────────────────────

# Keyword → rule type mapping
_BOUNDARY_KEYWORDS = [
    r"never\s+import",
    r"must\s+not\s+import",
    r"cannot\s+import",
    r"no\s+cross[- ]?(?:module|layer|domain)",
    r"frontend\s+must\s+not",
    r"backend\s+must\s+not",
]

_SECURITY_KEYWORDS = [
    r"no\s+hardcoded\s+secrets?",
    r"no\s+(?:eval|exec|pickle|marshal)\b",
    r"parameterized\s+queries?",
    r"no\s+sql\s+injection",
    r"no\s+xss",
    r"no\s+debug\s+mode",
    r"use\s+https",
    r"no\s+plaintext\s+passwords?",
]

_CONVENTION_KEYWORDS = [
    r"(?:services?|functions?|methods?|classes?)\s+under\s+(\d+)\s+lines?",
    r"max\s+(?:file|function|method|class)\s+size\s+(\d+)",
    r"all\s+api\s+routes?\s+need\s+tests?",
    r"all\s+routes?\s+must\s+have?\s+(?:unit\s+)?tests?",
    r"(?:snake_case|camelCase|PascalCase)\s+(?:for|in)\s+(.+)",
    r"tests?\s+(?:for|covering)\s+(?:all\s+)?(.+)",
    r"no\s+(?:globals?|singletons?)\b",
    r"max\s+file\s+(?:size|length)\s+(\d+)",
]

_STACK_KEYWORDS = [
    r"this\s+is\s+a?\s*(.+?)\s+(?:project|app|application|service|monorepo)",
    r"(?:using|built\s+with|stack)\s+(.+)",
    r"languages?\s*:\s*(.+)",
    r"framework(?:s)?:\s*(.+)",
]


def parse_nl_to_rules(text: str) -> list[CharterRule]:
    """Parse a natural language charter into structured rules.

    This is a heuristic parser — no AI tokens needed.  It extracts
    boundary, security, convention, and stack rules from NL text.
    """
    rules: list[CharterRule] = []
    lower = text.lower()
    counter: dict[str, int] = {}

    def _next_id(rule_type: RuleType) -> str:
        prefix = rule_type.value[:4]
        counter[prefix] = counter.get(prefix, 0) + 1
        return f"{prefix}-{counter[prefix]:03d}"

    # ── Boundary rules ───────────────────────────────────────────────────
    for pattern in _BOUNDARY_KEYWORDS:
        for m in re.finditer(pattern, lower):
            # Try to extract source/target from surrounding context
            ctx = text[max(0, m.start() - 50) : m.end() + 50]
            rules.append(
                CharterRule(
                    id=_next_id(RuleType.BOUNDARY),
                    type=RuleType.BOUNDARY,
                    description=m.group(0).strip(),
                    severity=Severity.HIGH,
                    metadata={"context": ctx.strip()},
                )
            )

    # ── Security rules ───────────────────────────────────────────────────
    for pattern in _SECURITY_KEYWORDS:
        for m in re.finditer(pattern, lower):
            rules.append(
                CharterRule(
                    id=_next_id(RuleType.SECURITY),
                    type=RuleType.SECURITY,
                    description=m.group(0).strip(),
                    severity=Severity.HIGH,
                    metadata={"pattern": m.group(0)},
                )
            )

    # ── Convention rules ─────────────────────────────────────────────────
    for pattern in _CONVENTION_KEYWORDS:
        for m in re.finditer(pattern, lower):
            desc = m.group(0).strip()
            meta: dict[str, Any] = {}
            # Extract numeric limits
            num_match = re.search(r"(\d+)\s+lines?", desc)
            if num_match:
                meta["max_lines"] = int(num_match.group(1))
            rules.append(
                CharterRule(
                    id=_next_id(RuleType.CONVENTION),
                    type=RuleType.CONVENTION,
                    description=desc,
                    severity=Severity.MEDIUM,
                    metadata=meta,
                )
            )

    # ── Stack rules ──────────────────────────────────────────────────────
    for pattern in _STACK_KEYWORDS:
        for m in re.finditer(pattern, lower):
            rules.append(
                CharterRule(
                    id=_next_id(RuleType.STACK),
                    type=RuleType.STACK,
                    description=m.group(0).strip(),
                    severity=Severity.LOW,
                    metadata={"raw": m.group(1).strip() if m.lastindex else m.group(0)},
                )
            )

    # De-duplicate by description
    seen: set[str] = set()
    unique: list[CharterRule] = []
    for r in rules:
        key = r.description.lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique


# ── Persistence ──────────────────────────────────────────────────────────────


def _charter_path(root: Path | None = None) -> Path:
    """Return the path to charter.json."""
    r = root or Path.cwd()
    return r / MEMORY_DIR / CHARTER_FILE


def load_charter(root: Path | None = None) -> Charter:
    """Load the charter from disk, or return an empty one."""
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
    """Save the charter to disk."""
    path = _charter_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(charter.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


# ── Drift detection ──────────────────────────────────────────────────────────


def check_boundary_violations(
    charter: Charter,
    import_edges: list[tuple[str, str]],
) -> list[CharterViolation]:
    """Check if any import edges violate boundary rules."""
    violations: list[CharterViolation] = []
    boundary_rules = [r for r in charter.rules if r.type == RuleType.BOUNDARY and r.enabled]

    if not boundary_rules:
        return violations

    # Build a map of subsystem keywords from boundary descriptions
    for rule in boundary_rules:
        desc_lower = rule.description.lower()
        # Try to extract "X must not import Y" or "no cross-module" patterns
        forbid_match = re.search(
            r"(?:from|import)\s+(\w+)\s+(?:must\s+not|cannot|never)\s+(?:import|depend)\s+(\w+)",
            desc_lower,
        )
        if forbid_match:
            source_sub = forbid_match.group(1)
            target_sub = forbid_match.group(2)
            for src, dst in import_edges:
                if source_sub in src.lower() and target_sub in dst.lower():
                    violations.append(
                        CharterViolation(
                            rule_id=rule.id,
                            rule_description=rule.description,
                            severity=rule.severity.value,
                            file_path=src,
                            message=f"'{src}' imports '{dst}' — violates boundary rule",
                            suggestion=f"Remove import of {target_sub} from {source_sub}",
                        )
                    )

    return violations


def check_convention_violations(
    charter: Charter,
    file_infos: list[Any],
) -> list[CharterViolation]:
    """Check if files/functions violate convention rules."""
    violations: list[CharterViolation] = []
    conv_rules = [r for r in charter.rules if r.type == RuleType.CONVENTION and r.enabled]

    if not conv_rules:
        return violations

    for rule in conv_rules:
        max_lines = rule.metadata.get("max_lines")
        if max_lines:
            for fi in file_infos:
                path_str = getattr(fi, "path", "")
                if path_str.endswith((".py", ".ts", ".js", ".go", ".java", ".rs")):
                    line_count = getattr(fi, "line_count", 0)
                    if line_count and line_count > max_lines:
                        violations.append(
                            CharterViolation(
                                rule_id=rule.id,
                                rule_description=rule.description,
                                severity=rule.severity.value,
                                file_path=path_str,
                                message=f"{path_str} is {line_count} lines (max {max_lines})",
                                suggestion=f"Split into smaller modules under {max_lines} lines",
                            )
                        )

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
