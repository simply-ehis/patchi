"""
Assurance package — provable properties over the scanned codebase.

The question this package exists to answer (UNIFIED_UPGRADE_PLAN.md):

    "What should be impossible, and can I prove it isn't?"

Structure:
    graph.py       — AssuranceGraph: claims, evidence, verdicts, persistence
    invariants.py  — invariant types + static verification engine
"""

from patchi.core.assurance.graph import (
    AssuranceGraph,
    Claim,
    Evidence,
    Verdict,
)
from patchi.core.assurance.invariants import (
    Invariant,
    InvariantType,
    verify_invariants,
)

__all__ = [
    "AssuranceGraph",
    "Claim",
    "Evidence",
    "Verdict",
    "Invariant",
    "InvariantType",
    "verify_invariants",
]
