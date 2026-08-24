"""
Security Orchestrator — deduplication, correlation, and composite risk scoring.

Receives raw AgentResult objects from all security agents and produces
a unified SecurityReport with deduplicated, correlated findings.

Deterministic first, AI second.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from patchi.core.agents.base import AgentResult, Finding

# ── Security Report ───────────────────────────────────────────────────────────


@dataclass
class CorrelatedFinding:
    """A deduplicated finding, possibly confirmed by multiple agents."""

    finding: Finding
    confirmed_by: list[str] = field(default_factory=list)
    composite_score: float = 0.0
    owasp_category: str = ""
    cwe_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.finding.to_dict()
        d["confirmed_by"] = self.confirmed_by
        d["composite_score"] = self.composite_score
        d["owasp_category"] = self.owasp_category
        d["cwe_ids"] = self.cwe_ids
        return d


@dataclass
class SecurityReport:
    """Unified output from all security agents after orchestration."""

    findings: list[CorrelatedFinding] = field(default_factory=list)
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_owasp: dict[str, int] = field(default_factory=dict)
    agents_run: list[str] = field(default_factory=list)
    correlation_count: int = 0

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "by_owasp": self.by_owasp,
            "agents_run": self.agents_run,
            "correlation_count": self.correlation_count,
            "findings": [f.to_dict() for f in self.findings],
        }


# ── OWASP Top 10 2021 mapping (CWE ranges) ──────────────────────────────────

_OWASP_MAPPING: dict | None = None
_OWASP_BY_CWE: dict[int, str] | None = None
_OWASP_KEYWORD_FALLBACK: dict[str, list[str]] | None = None

_MAPPING_FILE = Path(__file__).parent / "owasp_mapping.json"


def _load_owasp_mapping() -> dict:
    """Load OWASP mapping from JSON file (cached)."""
    global _OWASP_MAPPING, _OWASP_BY_CWE, _OWASP_KEYWORD_FALLBACK
    if _OWASP_MAPPING is not None:
        return _OWASP_MAPPING

    with open(_MAPPING_FILE, encoding="utf-8") as f:
        data = json.load(f)

    # Build lookup: CWE number → full category name (e.g. "A01:2021 Broken Access Control")
    by_cwe: dict[int, str] = {}
    for cat in data["categories"]:
        name = f"{cat['code']}:2021 {cat['name']}"
        for cwe in cat["cwes"]:
            by_cwe[cwe] = name

    _OWASP_MAPPING = data
    _OWASP_BY_CWE = by_cwe
    _OWASP_KEYWORD_FALLBACK = data.get("keyword_fallback", {})
    return data


def _classify_owasp(finding: Finding) -> str:
    """Map a finding to an OWASP Top 10 category via CWE ID or keyword fallback."""
    _load_owasp_mapping()
    cwe_str = finding.cwe.upper().replace("CWE-", "").strip()
    if cwe_str.isdigit() and _OWASP_BY_CWE is not None:
        cwe_num = int(cwe_str)
        if cwe_num in _OWASP_BY_CWE:
            return _OWASP_BY_CWE[cwe_num]
    # Fallback by finding type keywords
    ftype = finding.type.lower()
    msg = finding.message.lower()
    combined = ftype + msg
    if _OWASP_KEYWORD_FALLBACK is not None:
        for code, keywords in _OWASP_KEYWORD_FALLBACK.items():
            if any(w in combined for w in keywords):
                # Map code back to full name via the mapping data
                for cat in _OWASP_MAPPING["categories"]:
                    if cat["code"] == code:
                        return f"{code}:2021 {cat['name']}"
    return "A05:2021 Security Misconfiguration"


# ── Composite risk score ─────────────────────────────────────────────────────

_SEV_WEIGHTS = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.5, "info": 0.0}


def _composite_score(finding: Finding, confirm_count: int) -> float:
    """0-100 score: severity + confirmation bonus + confidence."""
    base = _SEV_WEIGHTS.get(finding.severity.value, 0.0)
    confirm_bonus = min(confirm_count * 3.0, 15.0)  # up to +15 for multi-agent confirmation
    return min(100.0, base * 10.0 + confirm_bonus)


# ── Orchestrator ─────────────────────────────────────────────────────────────


class SecurityOrchestrator:
    """
    Takes raw AgentResult list, deduplicates, correlates, scores.

    Usage:
        orch = SecurityOrchestrator()
        report = orch.correlate(agent_results)
    """

    def correlate(self, results: list[AgentResult]) -> SecurityReport:
        all_findings: list[Finding] = []
        agents_run = []

        for r in results:
            agents_run.append(r.agent_name)
            all_findings.extend(r.findings)

        # Step 1: Group by (file, type, cwe) with line-tolerance window (LIMIT-08)
        LINE_TOLERANCE = 5
        groups: dict[tuple, list[Finding]] = {}
        used: set[tuple] = set()
        for f in sorted(all_findings, key=lambda x: (x.file, x.line)):
            cwe_key = f.cwe.upper().replace("CWE-", "").strip() if f.cwe else ""
            # Try exact match first
            exact_key = (f.file, f.line, f.type, cwe_key)
            if exact_key not in used:
                # Try line-tolerance match within same file + type + cwe
                matched = False
                for tolerance_line in range(
                    max(1, f.line - LINE_TOLERANCE), f.line + LINE_TOLERANCE + 1
                ):
                    tol_key = (f.file, tolerance_line, f.type, cwe_key)
                    if tol_key in used:
                        matched = True
                        break
                if not matched:
                    key = (f.file, f.line, f.type, cwe_key)
                    used.add(key)
                    groups[key] = [f]
                else:
                    # Add to existing tolerance group
                    for gkey in groups:
                        if (
                            gkey[0] == f.file
                            and gkey[2] == f.type
                            and gkey[3] == cwe_key
                            and abs(gkey[1] - f.line) <= LINE_TOLERANCE
                        ):
                            groups[gkey].append(f)
                            break
            else:
                groups[exact_key].append(f)

        correlated: list[CorrelatedFinding] = []

        for key, group in groups.items():
            primary = group[0]
            confirmed_by = list({f.agent for f in group})
            owasp = _classify_owasp(primary)
            cwe_ids = list({f.cwe for f in group if f.cwe})

            score = _composite_score(primary, len(confirmed_by))

            # Take highest severity from the group
            best = max(group, key=lambda f: f.severity.sort_key())

            correlated.append(
                CorrelatedFinding(
                    finding=best,
                    confirmed_by=confirmed_by,
                    composite_score=score,
                    owasp_category=owasp,
                    cwe_ids=cwe_ids,
                )
            )

        # Sort by composite score descending (most dangerous first)
        correlated.sort(key=lambda c: (-c.composite_score, c.finding.file, c.finding.line))

        # Build summary
        by_sev: dict[str, int] = {}
        by_owasp: dict[str, int] = {}
        for c in correlated:
            sev = c.finding.severity.value
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_owasp[c.owasp_category] = by_owasp.get(c.owasp_category, 0) + 1

        return SecurityReport(
            findings=correlated,
            total_findings=len(correlated),
            by_severity=by_sev,
            by_owasp=by_owasp,
            agents_run=agents_run,
            correlation_count=sum(1 for c in correlated if len(c.confirmed_by) > 1),
        )
