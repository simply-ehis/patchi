"""
Compliance Report Generator — Evidence packs for hosted mode.

Aggregates scan results, health score, audit log, and domain control status
into a single structured report suitable for auditors / customers.
Deterministic: built entirely from data already on disk (no AI required).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

_log = logging.getLogger("patchi.hosted.compliance")

# Map Patchi security agents to compliance framework domains
_FRAMEWORK_MAPS: dict[str, dict[str, list[str]]] = {
    "owasp-asvs": {
        "V1: Architecture": ["AppMapperAgent", "BlastRadiusAgent", "PlanAuditorAgent"],
        "V2: Authentication": [
            "AuthenticationAuditAgent",
            "JWTSecurityAgent",
            "SessionManagementAgent",
            "SecretScanner",
        ],
        "V3: Session Management": ["SessionManagementAgent", "JWTSecurityAgent"],
        "V4: Access Control": ["AuthZAgent", "InjectionAgent"],
        "V5: Validation & Encoding": ["InjectionAgent", "TaintAnalyzer", "SensitiveDataAgent"],
        "V6: Stored Cryptography": ["CryptoAgent", "SecretsGuard"],
        "V7: Error Handling & Logging": ["HistoryAgent", "GovernanceAgent"],
        "V8: Data Protection": ["PrivacyAgent", "SensitiveDataAgent"],
        "V9: Communications": ["NetworkAgent", "SSRFProtectionAgent", "CORSAuditor"],
        "V10: Malicious Code": ["SupplyChainAgent", "DependencyVulnerabilityAgent"],
        "V12: Files & Resources": ["MisconfigAgent", "ConfigAuditAgent"],
        "V14: Configuration": [
            "ConfigAuditAgent",
            "HeaderAuditAgent",
            "RateLimitAuditor",
            "EnvVarValidator",
        ],
    },
    "pci-dss": {
        "Req 2: Secure Configs": ["ConfigAuditAgent", "MisconfigAgent", "HeaderAuditAgent"],
        "Req 3: Protect Stored Data": ["SecretScanner", "SensitiveDataAgent", "CryptoAgent"],
        "Req 4: Encrypt Transmission": ["NetworkAgent", "CryptoAgent"],
        "Req 5: Malware Protection": ["SupplyChainAgent"],
        "Req 6: Secure Development": [
            "TaintAnalyzer",
            "InjectionAgent",
            "DependencyVulnerabilityAgent",
        ],
        "Req 8: Identify & Auth": ["AuthenticationAuditAgent", "JWTSecurityAgent"],
        "Req 10: Log & Monitor": ["HistoryAgent", "GovernanceAgent", "EnvVarValidator"],
    },
}


def generate_report(root: Path, standard: str = "owasp-asvs") -> dict:
    """Build a structured compliance evidence report from disk state.

    Returns {standard, generated_at, controls: [...], summary: {...}} where
    each control row carries pass/fail/pending status plus the agent evidence
    behind it. Never raises — missing data becomes 'pending'.
    """
    from patchi.core import memory as mem

    framework = _FRAMEWORK_MAPS.get(standard)
    if framework is None:
        return {"error": f"Unknown standard '{standard}'. Supported: {', '.join(_FRAMEWORK_MAPS)}"}

    scans = mem.get_scan_results(root)
    brain = mem.get_brain(root)
    health = brain.get("health_score", {})

    def _agent_findings(agent: str) -> list[dict]:
        return [f for f in scans.get(agent, {}).get("findings", []) if isinstance(f, dict)]

    def _severity_counts(findings: list[dict]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    sections: list[dict] = []
    total_pass = total_fail = total_pending = 0

    for section_name, agents in framework.items():
        rows = []
        for agent in agents:
            findings = _agent_findings(agent)
            counts = _severity_counts(findings)

            if agent not in scans:
                status, evidence = "pending", f"{agent} has not run yet"
            elif counts.get("critical", 0) or counts.get("high", 0):
                status = "fail"
                evidence = (
                    f"{counts.get('critical', 0)} critical / {counts.get('high', 0)} high finding(s) from {agent}"
                )
            elif findings:
                status = "pass_with_notes"
                evidence = f"{len(findings)} low/medium finding(s) from {agent}"
            else:
                status = "pass"
                evidence = f"{agent} ran clean"

            if status == "fail":
                total_fail += 1
            elif status == "pending":
                total_pending += 1
            else:
                total_pass += 1

            rows.append({"control_agent": agent, "status": status, "evidence": evidence})

        sections.append(
            {
                "section": section_name,
                "controls": rows,
                "failed": sum(1 for r in rows if r["status"] == "fail"),
                "total": len(rows),
            }
        )

    return {
        "standard": standard,
        "generated_at": datetime.now(UTC).isoformat(),
        "project": {
            "purpose": brain.get("project_purpose", ""),
            "domain": brain.get("project_domain", ""),
            "framework": brain.get("framework", ""),
            "file_count": brain.get("file_count", 0),
        },
        "health_score": health.get("total"),
        "summary": {
            "sections": len(sections),
            "controls_total": sum(s["total"] for s in sections),
            "controls_failed": total_fail,
            "controls_passed": total_pass,
            "controls_pending": total_pending,
            # Simple posture rollout: pass ratio over evaluated controls
            "posture_pct": round(total_pass / max(1, total_pass + total_fail) * 100, 1),
        },
        "sections": sections,
    }
