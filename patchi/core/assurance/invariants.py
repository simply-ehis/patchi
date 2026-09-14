"""
Invariant engine — what should be impossible, checked statically.

Each Invariant pairs a property statement with a static verifier that runs
over project data (routes, findings, config). Verification produces Evidence;
the AssuranceGraph decides the verdict.

InvariantType mirrors UNIFIED_UPGRADE_PLAN.md's semantics:
    MUST          — property must hold unconditionally
    MUST_NOT      — named condition must never occur
    ONLY_IF       — action permitted only under stated precondition
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_log = logging.getLogger("patchi.core.assurance.invariants")


class InvariantType(StrEnum):
    MUST = "must"
    MUST_NOT = "must_not"
    ONLY_IF = "only_if"


@dataclass
class Invariant:
    """One provable property about the project."""

    id: str  # stable slug
    invariant_type: InvariantType
    statement: str  # human-readable property
    domain: str  # owning domain tag
    severity_if_disproved: str = "high"

    # verifier(project_data) -> (supports: bool, detail: str, artifact: dict)
    # project_data keys available: routes(IntentReport|None), findings(list[dict]),
    #                              config(dict), files(set[str])
    verifier: Callable[[dict], tuple[bool, str, dict]] | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.invariant_type.value,
            "statement": self.statement,
            "domain": self.domain,
            "severity_if_disproved": self.severity_if_disproved,
        }


def verify_invariants(
    invariants: list[Invariant],
    project_data: dict[str, Any],
):
    """
    Run every invariant's verifier against project_data.

    Returns list of (invariant, supports, detail, artifact) tuples.
    Invariants without a verifier yield NOT_PROVED evidence (never silently
    proved — honesty rule).
    """
    results = []
    for inv in invariants:
        if inv.verifier is None:
            results.append((inv, False, "no verifier registered for this invariant", {}))
            continue
        try:
            supports, detail, artifact = inv.verifier(project_data)
            results.append((inv, bool(supports), detail, artifact))
        except Exception as e:  # noqa: BLE001 — a broken check is NOT_PROVED
            _log.warning("invariant %s verifier failed: %s", inv.id, e)
            results.append((inv, False, f"verifier error: {e}", {}))
    return results


# ── Built-in invariant library ────────────────────────────────────────────────


def _check_all_writes_authenticated(data: dict) -> tuple[bool, str, dict]:
    """Every state-changing route must carry an auth guard."""
    report = data.get("routes")
    if report is None or not getattr(report, "routes", None):
        return False, "no route data available", {}
    bad = [r for r in report.routes if r.method.lower() in ("post", "put", "delete", "patch") and not r.has_auth_guard]
    total_writes = sum(1 for r in report.routes if r.method.lower() in ("post", "put", "delete", "patch"))
    if not total_writes:
        return False, "no state-changing routes discovered", {}
    artifact = {"unguarded": [r.file + ":" + str(r.line) for r in bad]}
    if bad:
        names = ", ".join(f"{r.path or '?'}" for r in bad[:3])
        return (
            False,
            f"{len(bad)}/{total_writes} write endpoints lack auth ({names}...)",
            artifact,
        )
    return True, f"all {total_writes} write endpoints carry auth guards", {}


def _check_no_hardcoded_secrets(data: dict) -> tuple[bool, str, dict]:
    """No finding of type hardcoded_secret may exist."""
    findings = data.get("findings", [])
    hits = [f for f in findings if "hardcoded_secret" in str(f.get("type", ""))]
    artifact = {"count": len(hits)}
    if hits:
        first = hits[0]
        return (
            False,
            f"{len(hits)} hardcoded secret(s), e.g. {first.get('file', '?')}:{first.get('line', 0)}",
            artifact,
        )
    return True, "no hardcoded secrets detected by scanners", {}


def _check_no_debug_mode(data: dict) -> tuple[bool, str, dict]:
    """Application must not run with debug enabled."""
    findings = data.get("findings", [])
    hits = [
        f
        for f in findings
        if "debug" in str(f.get("type", "")).lower() and f.get("severity", "").lower() in ("high", "critical")
    ]
    if hits:
        return (
            False,
            f"{len(hits)} debug-enabled finding(s) at high+ severity",
            {"count": len(hits)},
        )
    return True, "no high+ debug-mode findings", {}


BUILTIN_INVARIANTS: list[Invariant] = [
    Invariant(
        id="auth-all-writes",
        invariant_type=InvariantType.MUST,
        statement="All state-changing endpoints require authentication",
        domain="access-control-authz",
        severity_if_disproved="critical",
        verifier=_check_all_writes_authenticated,
    ),
    Invariant(
        id="secrets-none-hardcoded",
        invariant_type=InvariantType.MUST_NOT,
        statement="No credentials committed to source",
        domain="secrets-runtime-management",
        severity_if_disproved="critical",
        verifier=_check_no_hardcoded_secrets,
    ),
    Invariant(
        id="debug-not-in-prod",
        invariant_type=InvariantType.MUST_NOT,
        statement="Debug mode is never enabled in production configuration",
        domain="configuration-hardening",
        severity_if_disproved="high",
        verifier=_check_no_debug_mode,
    ),
]
