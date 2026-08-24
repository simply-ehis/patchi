"""
AssuranceGraph — a directed graph of claims backed by evidence.

Every security/quality property Patchi asserts becomes a Claim:

    property ("all state-changing routes require auth")
      <- Evidence (route scan: 4 routes, 1 unguarded)
      <- Verdict (proved / not-proved / disproved + timestamp)

The graph persists to ``.patchi/assurance.json`` so campaigns accumulate
across runs instead of evaporating with each scan. Honesty rule (2.1-1):
a claim without evidence is NEVER reported as proved, and a disproved
claim keeps its repair history — the system records what it tried, not
just what it wanted to be true.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.core.assurance.graph")

ASSURANCE_FILE = ".patchi/assurance.json"


class Verdict(str, Enum):
    """Outcome of verifying a claim. No evidence => UNPROVEN, never 'proved'."""

    PROVED = "proved"
    NOT_PROVED = "not_proved"      # couldn't establish (insufficient evidence)
    DISPROVED = "disproved"        # positive counter-evidence found
    UNPROVEN = "unproven"          # never checked


@dataclass
class Evidence:
    """One piece of supporting/refuting observation for a claim."""

    source: str            # what produced it: "intent_scan", "secret_scan", ...
    detail: str            # human-readable observation
    supports: bool         # True = supports claim; False = refutes
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    artifact: dict = field(default_factory=dict)  # machine-checkable payload

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "detail": self.detail,
            "supports": self.supports,
            "timestamp": self.timestamp,
            "artifact": self.artifact,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        return cls(
            source=d.get("source", "?"),
            detail=d.get("detail", ""),
            supports=bool(d.get("supports", False)),
            timestamp=d.get("timestamp", ""),
            artifact=d.get("artifact", {}),
        )


@dataclass
class Claim:
    """A property asserted about the project, with its evidence trail."""

    id: str                              # stable slug, e.g. "auth-all-writes"
    statement: str                       # human-readable property
    domain: str                          # owning domain tag, e.g. "auth-session"
    severity_if_disproved: str = "high"
    verdict: Verdict = Verdict.UNPROVEN
    evidence: list[Evidence] = field(default_factory=list)
    repairs: list[dict] = field(default_factory=list)  # adversarial-repair chain
    updated_at: str = ""

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self.updated_at = ev.timestamp
        # Verdict recomputation: ANY refuting evidence wins (honesty-first);
        # otherwise proved only if >=1 supporting evidence exists.
        refuting = [e for e in self.evidence if not e.supports]
        supporting = [e for e in self.evidence if e.supports]
        if refuting:
            self.verdict = Verdict.DISPROVED
        elif supporting:
            self.verdict = Verdict.PROVED
        else:
            self.verdict = Verdict.NOT_PROVED

    def record_repair(self, description: str, outcome: str) -> None:
        """Record one loop of the adversarial repair chain."""
        self.repairs.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "description": description,
            "outcome": outcome,
        })
        # A repair attempt resets the verdict until re-verified.
        self.verdict = Verdict.NOT_PROVED

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "statement": self.statement,
            "domain": self.domain,
            "severity_if_disproved": self.severity_if_disproved,
            "verdict": self.verdict.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "repairs": self.repairs,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Claim":
        c = cls(
            id=d.get("id", "?"),
            statement=d.get("statement", ""),
            domain=d.get("domain", "general"),
            severity_if_disproved=d.get("severity_if_disproved", "high"),
            verdict=Verdict(d.get("verdict", "unproven")),
            updated_at=d.get("updated_at", ""),
        )
        c.evidence = [Evidence.from_dict(e) for e in d.get("evidence", [])]
        c.repairs = list(d.get("repairs", []))
        return c


@dataclass
class AssuranceGraph:
    """The persistent collection of claims for one project."""

    claims: dict[str, Claim] = field(default_factory=dict)

    def upsert_claim(
        self,
        claim_id: str,
        statement: str,
        domain: str = "general",
        severity_if_disproved: str = "high",
    ) -> Claim:
        """Get-or-create a claim; preserves existing evidence across runs."""
        if claim_id not in self.claims:
            self.claims[claim_id] = Claim(
                id=claim_id,
                statement=statement,
                domain=domain,
                severity_if_disproved=severity_if_disproved,
            )
        return self.claims[claim_id]

    def attach_evidence(self, claim_id: str, evidence: Evidence) -> Claim:
        claim = self.claims[claim_id]  # KeyError = programming error upstream
        claim.add_evidence(evidence)
        return claim

    # ── Reporting ───────────────────────────────────────────────────────────

    def coverage(self) -> dict[str, Any]:
        """Assurance status summary. Never says 'secure' — says what's proved."""
        total = len(self.claims)
        by_verdict: dict[str, int] = {}
        by_domain: dict[str, dict[str, int]] = {}
        for c in self.claims.values():
            by_verdict[c.verdict.value] = by_verdict.get(c.verdict.value, 0) + 1
            dom = by_domain.setdefault(c.domain, {"proved": 0, "total": 0})
            dom["total"] += 1
            if c.verdict == Verdict.PROVED:
                dom["proved"] += 1

        disproved = [
            c for c in self.claims.values() if c.verdict == Verdict.DISPROVED
        ]
        return {
            "claims_total": total,
            "by_verdict": by_verdict,
            "by_domain": by_domain,
            "disproved_claims": [c.to_dict() for c in disproved],
            "statement": (
                f"{by_verdict.get('proved', 0)}/{total} properties proved; "
                f"{len(disproved)} violated"
                if total
                else "no properties established yet"
            ),
        }

    # ── Persistence ─────────────────────────────────────────────────────────

    def save(self, root: Path) -> Path:
        path = root / ASSURANCE_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "claims": [c.to_dict() for c in self.claims.values()],
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json_dumps(payload), encoding="utf-8"
        )
        tmp.replace(path)
        return path

    @classmethod
    def load(cls, root: Path) -> "AssuranceGraph":
        path = root / ASSURANCE_FILE
        g = cls()
        if not path.is_file():
            return g
        try:
            import json

            data = json.loads(path.read_text(encoding="utf-8"))
            for cd in data.get("claims", []):
                try:
                    c = Claim.from_dict(cd)
                    g.claims[c.id] = c
                except Exception as e:  # noqa: BLE001 — skip corrupt entries
                    _log.warning("skipping corrupt assurance claim: %s", e)
        except Exception as e:  # noqa: BLE001 — corrupt file = fresh graph
            _log.warning("failed to load assurance graph: %s", e)
        return g


def json_dumps(payload: Any) -> str:
    import json

    return json.dumps(payload, indent=2, default=str)
