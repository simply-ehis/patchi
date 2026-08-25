"""
Tool Adapters — shared normalization for external SAST tools (bandit, pysa, codeql).

Every wrapper agent used to hand-build Finding objects and crash on the
first finding (Severity("MEDIUM") vs lowercase enum; nonexistent
``confidence=`` kwarg). This module is the single honest conversion layer:

    normalize_severity(raw)   -> Severity   (every known convention)
    make_tool_finding(...)    -> Finding    (valid fields, provenance kept)

Max-potential details preserved instead of discarded:
  - the TOOL's own confidence tier (bandit HIGH/MEDIUM/LOW) lands in
    ``extra["tool_confidence"]`` so the ConfidenceGate can weigh it;
  - a code snippet rides along in ``code_snippet`` — the gate's
    method-precision scorer needs it, and AI review gets real context;
  - numeric SARIF security-severity (0.0-10.0) maps to severity bands.
"""

from __future__ import annotations

from typing import Any

from patchi.core.agents.base import Finding, Severity

# ── Severity normalization ───────────────────────────────────────────────────

_WORD_MAP: dict[str, str] = {
    # bandit / generic uppercase
    "LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "critical",
    # already-lowercase passthrough
    "low": "low", "medium": "medium", "high": "high",
    "critical": "critical", "info": "info", "informational": "info",
    # compiler-style levels (pysa/codeql text output)
    "ERROR": "high", "WARNING": "medium", "WARN": "medium",
    "NOTE": "info", "NOTICE": "info", "SEGMENT": "info",
}

_DEFAULT = "medium"


def normalize_severity(raw: Any, default: str = _DEFAULT) -> Severity:
    """Map any tool's severity spelling to our Severity enum. Never raises."""
    if isinstance(raw, (int, float)):
        return Severity(_numeric_band(float(raw)))
    value = str(raw).strip() if raw is not None else ""
    mapped = _WORD_MAP.get(value)
    if mapped is None:
        # last resort: case-insensitive lookup
        mapped = _WORD_MAP.get(value.upper(), default)
        if mapped not in ("low", "medium", "high", "critical", "info"):
            mapped = default
    try:
        return Severity(mapped)
    except ValueError:
        return Severity(default)


def _numeric_band(score_0_to_10: float) -> str:
    """CodeQL SARIF security-severity banding."""
    if score_0_to_10 >= 9.0:
        return "critical"
    if score_0_to_10 >= 7.0:
        return "high"
    if score_0_to_10 >= 4.0:
        return "medium"
    return "low"


# ── Tool confidence tiers ────────────────────────────────────────────────────

_TIER_MAP = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}


def tool_confidence(raw: Any, default: float = 0.5) -> float:
    """Bandit-style HIGH/MEDIUM/LOW tier -> float; passthrough numbers."""
    if isinstance(raw, (int, float)):
        return max(0.0, min(1.0, float(raw)))
    return _TIER_MAP.get(str(raw).strip().upper(), default)


# ── Finding construction ─────────────────────────────────────────────────────

def make_tool_finding(
    agent: str,
    ftype: str,
    raw_severity: Any,
    file: str,
    line: int,
    message: str,
    cwe: str = "",
    snippet: str = "",
    confidence_raw: Any = None,
    extra: dict | None = None,
) -> Finding:
    """Build one valid Finding from a raw tool record. Never raises for data."""
    payload_extra: dict = {"tool": agent}
    conf = None
    if confidence_raw is not None:
        conf = tool_confidence(confidence_raw)
        payload_extra["tool_confidence"] = conf
    if extra:
        payload_extra.update(extra)

    kwargs: dict[str, Any] = {}
    if snippet:
        kwargs["code_snippet"] = str(snippet)[:500]

    return Finding(
        agent=agent,
        type=(ftype or f"{agent.lower()}_finding")[:80],
        severity=normalize_severity(raw_severity),
        file=file or "",
        line=int(line or 0),
        message=str(message or "")[:400],
        cwe=str(cwe or ""),
        extra=payload_extra,
        **kwargs,
    )
