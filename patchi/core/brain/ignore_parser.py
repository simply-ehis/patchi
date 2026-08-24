"""
Ignore lists with expiry for Patchi.

Parses inline ignore comments in source code:
  - // patchi-ignore: RULE_NAME YYYY-MM-DD
  - # patchi-ignore: RULE_NAME YYYY-MM-DD
  - /* patchi-ignore: RULE_NAME YYYY-MM-DD */
  - -- patchi-ignore: RULE_NAME YYYY-MM-DD

Reports expired ignores as findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from patchi.core.agents.base import Finding, Severity, safe_rglob

# Match: comment_start patchi-ignore: RULE_NAME YYYY-MM-DD [optional reason]
IGNORE_PATTERN = re.compile(
    r"""(?P<comment>[#*\/;{]+)\s*
        patchi-?ignore\s*:\s*
        (?P<rule>\S+)\s*
        (?P<expiry>\d{4}-\d{2}-\d{2})
        (?P<reason>.*?)?       # optional reason after date
        (?P<close>\*\/)?        # optional */ close for block comments
    """,
    re.IGNORECASE | re.VERBOSE,
)


import logging
_log = logging.getLogger("patchi.brain.ignore_parser")

@dataclass
class IgnoreDirective:
    """A single patchi-ignore directive found in source."""

    file: str
    line: int
    rule: str
    expiry: date
    reason: str = ""
    expired: bool = False
    raw: str = ""


def scan_ignore_directives(root: Path) -> list[IgnoreDirective]:
    """
    Scan all source files for patchi-ignore directives.
    Returns list of all directives found, annotated with expired status.
    """
    directives: list[IgnoreDirective] = []
    today = date.today()

    source_patterns = [
        "*.py", "*.js", "*.jsx", "*.ts", "*.tsx",
        "*.java", "*.go", "*.rs", "*.c", "*.h",
        "*.cpp", "*.cxx", "*.cc", "*.hpp", "*.rb",
        "*.swift", "*.kt", "*.kts", "*.yaml", "*.yml",
        "*.json", "*.toml", "*.html", "*.css", "*.scss",
    ]

    for pattern in source_patterns:
        for file_path in safe_rglob(root, pattern):
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception as e:
                _log.warning("scan_ignore_directives failed: %s", e)
                continue

            rel_path = file_path.relative_to(root).as_posix()
            lines = content.splitlines()

            for line_num, line in enumerate(lines, 1):
                for match in IGNORE_PATTERN.finditer(line):
                    try:
                        expiry_date = datetime.strptime(match.group("expiry"), "%Y-%m-%d").date()
                    except ValueError:
                        continue

                    try:
                        reason = match.group("reason") or ""
                    except IndexError:
                        reason = ""

                    directives.append(
                        IgnoreDirective(
                            file=rel_path,
                            line=line_num,
                            rule=match.group("rule").strip(),
                            expiry=expiry_date,
                            reason=reason.strip(),
                            expired=expiry_date < today,
                            raw=line.strip(),
                        )
                    )

    return directives


def find_expired_ignores(root: Path) -> list[IgnoreDirective]:
    """Return only expired ignore directives."""
    return [d for d in scan_ignore_directives(root) if d.expired]


def findings_from_expired_ignores(root: Path) -> list[Finding]:
    """Convert expired ignore directives into findings."""
    findings: list[Finding] = []
    for d in find_expired_ignores(root):
        findings.append(
            Finding(
                agent="IgnoreParser",
                type="expired_ignore_directive",
                severity=Severity.MEDIUM,
                file=d.file,
                line=d.line,
                message=f"Expired patchi-ignore for '{d.rule}'",
                detail=(
                    f"The patchi-ignore directive for rule '{d.rule}' expired on {d.expiry}. "
                    f"Either remove the suppression or update the expiry date if the issue persists."
                ),
                code_snippet=d.raw,
                suggestion=f"Remove the ignore or set a new expiry: patchi-ignore: {d.rule} YYYY-MM-DD",
                extra={"expiry": d.expiry.isoformat(), "rule": d.rule},
            )
        )
    return findings
