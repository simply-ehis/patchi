"""
Documentation synthesis — project purpose → structured SynthesisResult.

Item 55: Explicit "unclear — no evidence found" fallback when the Brain's
purpose inference returns an empty, vague, or "unclear" result.  The zero-doc
path always returns a complete SynthesisResult with safe defaults so no
downstream consumer ever sees a partial object.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

_log = logging.getLogger("patchi.brain.doc_synthesizer")

_UNCLEAR_PURPOSE = "unclear — no evidence found"


@dataclass
class SynthesisResult:
    """Structured output of project-purpose synthesis.

    Every field has a safe default so that ``SynthesisResult()`` is always
    a complete, usable object — never ``None`` or partially filled.
    """

    purpose: str = _UNCLEAR_PURPOSE
    domain: str = "unknown"
    user_stories: list[str] = field(default_factory=list)
    api_surface: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    key_modules: list[str] = field(default_factory=list)
    security_domains: list[str] = field(default_factory=list)
    summary: str = "Project purpose could not be determined from available signals."

    def to_dict(self) -> dict:
        return {
            "purpose": self.purpose,
            "domain": self.domain,
            "user_stories": self.user_stories,
            "api_surface": self.api_surface,
            "entry_points": self.entry_points,
            "key_modules": self.key_modules,
            "security_domains": self.security_domains,
            "summary": self.summary,
        }


def _is_unclear(purpose: str | None) -> bool:
    """True when a purpose string carries no actionable signal."""
    if not purpose:
        return True
    lower = purpose.lower().strip()
    if lower in ("", "unknown", "unclear"):
        return True
    # The Brain's own "unclear" fallback message.
    if "unclear" in lower and "no identifying dependencies" in lower:
        return True
    return False


def build_synthesis(
    purpose: str | None,
    domain: str | None = None,
    *,
    file_purposes: list[str] | None = None,
    route_paths: list[str] | None = None,
    entry_points: list[str] | None = None,
    security_domains: list[str] | None = None,
) -> SynthesisResult:
    """Build a SynthesisResult from the Brain's purpose + scan artefacts.

    When *purpose* is unclear/empty, the zero-doc fallback fires: a warning
    is emitted and a fully-populated SynthesisResult with safe defaults is
    returned.  A partial object is never produced.
    """
    if _is_unclear(purpose):
        return _build_zero_doc_result(
            domain=domain,
            security_domains=security_domains,
        )

    # ── Normal path — purpose is actionable ────────────────────────────────
    user_stories = _derive_user_stories(purpose or "", file_purposes or [])
    api_surface = _derive_api_surface(route_paths or [])
    key_modules = _derive_key_modules(file_purposes or [])

    return SynthesisResult(
        purpose=purpose or _UNCLEAR_PURPOSE,
        domain=domain or "unknown",
        user_stories=user_stories,
        api_surface=api_surface,
        entry_points=entry_points or [],
        key_modules=key_modules,
        security_domains=security_domains or [],
        summary=f"Project purpose: {purpose}",
    )


def _build_zero_doc_result(
    *,
    domain: str | None = None,
    security_domains: list[str] | None = None,
) -> SynthesisResult:
    """Fallback when no purpose evidence was found.

    Returns a complete SynthesisResult — every field is populated with a safe
    default so downstream consumers never see ``None`` or partial objects.
    A warning is logged so operators know the pipeline fell back.
    """
    _log.warning(
        "Doc synthesis fallback: project purpose is unclear — no evidence found. "
        "Returning safe defaults. Domain=%s, security_domains=%s",
        domain,
        security_domains,
    )
    return SynthesisResult(
        purpose=_UNCLEAR_PURPOSE,
        domain=domain or "unknown",
        user_stories=[],
        api_surface=[],
        entry_points=[],
        key_modules=[],
        security_domains=security_domains or [],
        summary=(
            "Project purpose could not be determined from available signals "
            "(no identifying dependencies, routes, or file purposes)."
        ),
    )


# ── Heuristic derivation helpers (normal path only) ────────────────────────


def _derive_user_stories(purpose: str, file_purposes: list[str]) -> list[str]:
    """Extract high-level user stories from purpose + file-level signals."""
    stories: list[str] = []
    if purpose:
        stories.append(f"As a user, I interact with: {purpose}")
    for fp in file_purposes[:5]:
        if fp and "(filename guess)" not in fp:
            stories.append(f"Module purpose: {fp}")
    return stories[:10]


def _derive_api_surface(route_paths: list[str]) -> list[str]:
    """List the public API surface from discovered routes."""
    return [f"/{p.lstrip('/')}" for p in route_paths[:30]]


def _derive_key_modules(file_purposes: list[str]) -> list[str]:
    """Pick the most informative module purposes as key modules."""
    return [
        fp for fp in file_purposes
        if fp and "(filename guess)" not in fp
    ][:10]
