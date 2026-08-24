"""
SARIF 2.1.0 export for Patchi findings.

Converts internal findings dicts into the SARIF format
for GitHub Code Scanning, GitLab SAST, and Azure DevOps integration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/v2.1.0/sarif-2-1-0.json"


def convert_findings(findings: list[dict], tool_name: str = "Patchi") -> dict:
    """Convert a list of Patchi findings to a SARIF 2.1.0 run object."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = f.get("type", "generic") or "generic"
        if rule_id not in rules:
            rules[rule_id] = _make_rule(rule_id, f)

        result = _make_result(rule_id, f)
        if result:
            results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "0.6.0",
                        "informationUri": "https://patchi.ai",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }


def _make_rule(rule_id: str, finding: dict) -> dict:
    sev = finding.get("severity", "warning")
    sarif_level = _sarif_level(sev)
    return {
        "id": rule_id,
        "name": rule_id.replace("_", " ").title(),
        "shortDescription": {"text": finding.get("message", rule_id)[:200]},
        "fullDescription": {"text": finding.get("detail", finding.get("message", ""))[:500]},
        "defaultConfiguration": {"level": sarif_level},
        "properties": {
            "tags": ["security"] if sev in ("critical", "high", "medium") else [],
            "precision": "high",
        },
    }


def _make_result(rule_id: str, finding: dict) -> dict | None:
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    if not file_path:
        return None

    sev = finding.get("severity", "warning")
    sarif_level = _sarif_level(sev)

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": sarif_level,
        "message": {"text": finding.get("message", "")[:500]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {
                        "startLine": max(line, 1),
                    },
                }
            }
        ],
    }

    cwe = finding.get("cwe", "")
    if cwe:
        result["properties"] = {"cwe": cwe}

    return result


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }.get(severity, "warning")


def export(findings: list[dict], output_path: Path) -> None:
    """Write a SARIF file from findings."""
    doc = convert_findings(findings)
    output_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
