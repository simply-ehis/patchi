"""Output-side secret scrubbing for reports and exports.

Detection-side redaction lives in security_taint (SecretScanner never stores
values). This module covers everything else an agent may embed in a finding's
message/evidence/snippet before it reaches a handoff surface (client report,
JSON/SARIF export, retest records).

Pattern-based scrubbing is the right tool here by construction (Part 7 §4
KEEP-AND-HARDEN: there is no structural proof that a string is a secret) —
prefixes are imported from SecretScanner, never duplicated, so the scrubber
can't drift from the detector.
"""

from __future__ import annotations

import logging
import re

_log = logging.getLogger("patchi.security.redact")

_PLACEHOLDER = "[REDACTED]"

# credential-looking assignment keys: value after = or : gets scrubbed when
# quoted and long enough to be real (short values are usually placeholders).
_ASSIGN_RE = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|"""
    r"""client[_-]?secret|private[_-]?key)\b\s*[:=]\s*(['"])(.{8,}?)\2"""
)

# Values that are obviously not real secrets — scrubbing them destroys
# readable examples and docs. Mirrors the detector's placeholder veto.
_PLACEHOLDERS = frozenset({
    "changeme", "example", "xxx", "test", "test123", "password",
    "password123", "123456", "qwerty", "asdf", "none", "null", "undefined",
})


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        not lowered
        or lowered in _PLACEHOLDERS
        or "example" in lowered
        or "<" in value
        or "*" in value
    )


# High-entropy blob candidates are found, then judged (length + entropy),
# never blindly replaced — prose must survive.
_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")


def _provider_prefixes() -> tuple[str, ...]:
    try:
        from patchi.core.security.security_taint import SecretScanner

        return tuple(p for p, _ in SecretScanner._PROVIDER_PREFIXES)
    except Exception as exc:
        _log.debug("provider prefix import failed: %s", exc)
        return ("AKIA", "ghp_", "gho_", "sk-ant-", "sk-proj-", "xoxb-", "AIza")


def _entropy(value: str) -> float:
    try:
        from patchi.core.security.security_taint import shannon_entropy

        return float(shannon_entropy(value))
    except Exception:
        return 0.0


def redact_text(text: str | None) -> str:
    """Scrub probable secret values from free text. Never raises."""
    if not text:
        return ""
    try:
        out = str(text)
        for prefix in _provider_prefixes():
            # ghp_XXXX... → ghp_[REDACTED] (prefix kept for identification)
            out = re.sub(
                re.escape(prefix) + r"[A-Za-z0-9._\-/+=]{8,}",
                prefix + _PLACEHOLDER,
                out,
            )
        def _assign(match: re.Match) -> str:
            if _is_placeholder(match.group(3)):
                return match.group(0)
            prefix = match.group(0)[: match.start(3) - match.start(0)]
            return prefix + _PLACEHOLDER + match.group(2)

        out = _ASSIGN_RE.sub(_assign, out)
        def _blob(match: re.Match) -> str:
            token = match.group(0)
            if len(token) >= 20 and _entropy(token) >= 3.5:
                return _PLACEHOLDER
            return token

        return _BLOB_RE.sub(_blob, out)
    except Exception as exc:
        _log.debug("redact_text failed: %s", exc)
        return str(text or "")


def redact_finding(finding: dict) -> dict:
    """Copy of a finding dict with free-text fields scrubbed.

    Identity fields (file/line/type/severity/cwe/agent) are untouched —
    matching, scoring, and retest diffing still work on redacted copies.
    """
    scrubbed = dict(finding)
    for key in ("message", "detail", "code_snippet", "evidence", "suggestion"):
        if scrubbed.get(key):
            scrubbed[key] = redact_text(scrubbed[key])
    return scrubbed
