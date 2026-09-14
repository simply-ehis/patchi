"""
Ignore Lists with Expiry §10.2.3 — // patchi-ignore: RULE YYYY-MM-DD

Parses inline ignore comments with expiry dates, warns on expired ignores.
Supports: //, #, <!--, /* */ styles across 11 langs.

Usage:
  findings = filter_ignores(findings, root)  # returns (kept, suppressed, expired_warnings)
"""

from __future__ import annotations

import logging
import re
from datetime import date, datetime
from pathlib import Path

_log = logging.getLogger("patchi.security.ignore_expiry")

# Matches: patchi-ignore, patchi_ignore, patchi:ignore optionally with : RULE and date YYYY-MM-DD or YYYY/MM/DD
_RE = re.compile(
    r"patchi[\-_:]?ignore\s*:?\s*(?P<rule>[\w\-\*]+)?\s*(?P<date>\d{4}[-/]\d{2}[-/]\d{2})?",
    re.IGNORECASE,
)


def _parse_ignore_line(line: str) -> tuple[str | None, date | None] | None:
    m = _RE.search(line)
    if not m:
        return None
    rule = m.group("rule")
    datestr = m.group("date")
    d = None
    if datestr:
        try:
            d = datetime.strptime(datestr.replace("/", "-"), "%Y-%m-%d").date()
        except ValueError:
            d = None
    # If no rule and no date, still a generic ignore (no expiry)
    if not rule and not d:
        return ("*", None)
    return (rule or "*", d)


def _is_expired(d: date | None) -> bool:
    return d is not None and d < date.today()


def scan_file_ignores(root: Path, rel: str) -> list[dict]:
    """Return list of {line, rule, expiry, expired} for a file."""
    out: list[dict] = []
    try:
        txt = (root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for i, line in enumerate(txt.splitlines(), 1):
        parsed = _parse_ignore_line(line)
        if parsed:
            rule, expiry = parsed
            out.append(
                {
                    "line": i,
                    "rule": rule,
                    "expiry": expiry.isoformat() if expiry else None,
                    "expired": _is_expired(expiry),
                }
            )
    return out


def filter_ignores(findings: list, root: Path) -> tuple[list, list, list]:
    """
    Filter findings suppressed by patchi-ignore comments.
    Returns (kept, suppressed, expired_warnings).

    A finding is suppressed if its file has a patchi-ignore comment
    on the same line, previous line, or file-header (line 1) with matching rule or "*"
    and not expired. Expired ignores generate warnings but do NOT suppress.
    """
    suppressed: list = []
    expired_warnings: list[dict] = []
    # cache per file ignores
    cache: dict[str, list[dict]] = {}

    def get_ignores(rel: str) -> list[dict]:
        if rel not in cache:
            cache[rel] = scan_file_ignores(root, rel)
        return cache[rel]

    kept: list = []
    for f in findings:
        rel = getattr(f, "file", "") or (f.get("file", "") if isinstance(f, dict) else "")
        line = getattr(f, "line", 0) or (f.get("line", 0) if isinstance(f, dict) else 0)
        ftype = getattr(f, "type", "") or (f.get("type", "") if isinstance(f, dict) else "")
        if not rel:
            kept.append(f)
            continue
        ignores = get_ignores(rel)
        matched = None
        for ig in ignores:
            # match rule: "*" or exact type or prefix
            rule = ig["rule"]
            if rule != "*" and rule.lower() not in ftype.lower() and ftype.lower() not in rule.lower():
                continue
            # line proximity: same line, previous line, or header
            if ig["line"] in (line, line - 1, 1):
                if ig["expired"]:
                    expired_warnings.append(
                        {
                            "file": rel,
                            "line": ig["line"],
                            "rule": rule,
                            "finding_type": ftype,
                            "message": f"Expired ignore {rule} expired {ig['expiry']}",
                        }
                    )
                    continue
                matched = ig
                break
        if matched:
            suppressed.append(f)
        else:
            kept.append(f)
    if expired_warnings:
        _log.warning("ignore expiry: %d expired ignores (not suppressing)", len(expired_warnings))
    return kept, suppressed, expired_warnings
