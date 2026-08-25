"""
Policy Engine — YAML/JSON policy enforcement for security compliance.

Loads policy definitions from .patchi/policies/ and enforces them
against code and findings. Supports SOC2, HIPAA, PCI-DSS, CIS packs.
"""

from __future__ import annotations

import json
import logging
import re

import yaml

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)

# ── Built-in policy packs ─────────────────────────────────────────────────────

_BUILTIN_POLICIES: dict[str, list[dict]] = {
    "soc2": [
        {
            "id": "SOC2-CC6.1",
            "name": "Access Control",
            "check": "no_default_credentials",
            "severity": "critical",
        },
        {
            "id": "SOC2-CC6.6",
            "name": "Encryption in Transit",
            "check": "no_plaintext_http",
            "severity": "high",
        },
        {"id": "SOC2-CC7.1", "name": "Logging", "check": "has_logging", "severity": "medium"},
        {
            "id": "SOC2-CC8.1",
            "name": "Change Management",
            "check": "has_audit_trail",
            "severity": "medium",
        },
    ],
    "hipaa": [
        {
            "id": "HIPAA-164.312",
            "name": "Access Control",
            "check": "no_default_credentials",
            "severity": "critical",
        },
        {
            "id": "HIPAA-164.312",
            "name": "Encryption",
            "check": "no_weak_crypto",
            "severity": "critical",
        },
        {
            "id": "HIPAA-164.312",
            "name": "Audit Controls",
            "check": "has_logging",
            "severity": "high",
        },
        {
            "id": "HIPAA-164.312",
            "name": "Data Integrity",
            "check": "no_hardcoded_secrets",
            "severity": "critical",
        },
    ],
    "pci_dss": [
        {
            "id": "PCI-DSS-2.1",
            "name": "No Default Credentials",
            "check": "no_default_credentials",
            "severity": "critical",
        },
        {
            "id": "PCI-DSS-3.4",
            "name": "Encryption",
            "check": "no_weak_crypto",
            "severity": "critical",
        },
        {
            "id": "PCI-DSS-6.5",
            "name": "Secure Development",
            "check": "no_sql_injection",
            "severity": "critical",
        },
        {
            "id": "PCI-DSS-10.2",
            "name": "Audit Trail",
            "check": "has_audit_trail",
            "severity": "high",
        },
    ],
    "cis": [
        {
            "id": "CIS-1.1",
            "name": "File Permissions",
            "check": "no_world_readable",
            "severity": "high",
        },
        {
            "id": "CIS-2.1",
            "name": "Software Updates",
            "check": "no_outdated_deps",
            "severity": "medium",
        },
        {"id": "CIS-4.1", "name": "Firewall", "check": "no_open_ports", "severity": "high"},
        {
            "id": "CIS-5.1",
            "name": "Password Policy",
            "check": "strong_passwords",
            "severity": "medium",
        },
    ],
}


_log = logging.getLogger("patchi.security.policy_engine")


def _check_policy(check_type: str, content: str, findings: list[Finding]) -> list[str]:
    """Run a policy check against file content. Returns list of violation messages."""
    violations = []

    if check_type == "no_default_credentials":
        if re.search(
            r'(?:admin|root|password)\s*[:=]\s*["\'](?:admin|root|password|changeme)["\']',
            content,
            re.I,
        ):
            violations.append("Default credentials found")

    elif check_type == "no_plaintext_http":
        if re.search(r"http://(?!localhost|127\.0\.0\.1)", content):
            violations.append("Plaintext HTTP URL found")

    elif check_type == "has_logging":
        if not re.search(r"(?:log|logging|logger|audit)", content, re.I):
            violations.append("No logging implementation found")

    elif check_type == "has_audit_trail":
        if not re.search(r"(?:audit|log|track|record)", content, re.I):
            violations.append("No audit trail found")

    elif check_type == "no_weak_crypto":
        if re.search(r"\b(?:MD5|SHA1|DES|RC4)\b", content, re.I):
            violations.append("Weak cryptographic algorithm detected")

    elif check_type == "no_hardcoded_secrets":
        if re.search(
            r'(?:api[_-]?key|secret|password)\s*[:=]\s*["\'][^"\']{8,}["\']', content, re.I
        ):
            violations.append("Hardcoded secret detected")

    elif check_type == "no_sql_injection":
        if re.search(r"(?:execute|query)\s*\([^)]*\+", content):
            violations.append("Potential SQL injection — string concatenation in query")

    elif check_type == "no_world_readable":
        if re.search(r"chmod\s+777|chmod\s+\+r", content):
            violations.append("World-readable file permissions")

    elif check_type == "no_outdated_deps":
        pass  # Handled by dependency scanner

    elif check_type == "no_open_ports":
        if re.search(r"EXPOSE\s+(?:22|3389)\b", content, re.I):
            violations.append("Sensitive port exposed")

    elif check_type == "strong_passwords":
        if re.search(r'(?:password|passwd)\s*[:=]\s*["\'][^"\']{1,7}["\']', content, re.I):
            violations.append("Weak password (less than 8 characters)")

    return violations


@register
class PolicyEngineAgent(BaseAgent):
    """Enforces YAML/JSON security policies against code."""

    name = "PolicyEngineAgent"
    group = AgentGroup.SECURITY
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Load policies from .patchi/policies/ or use built-in packs
        policy_packs = self._load_policies(inp)

        # Flatten all rules once — avoids re-iterating packs per file
        all_rules: list[tuple[str, dict]] = []  # (pack_name, rule)
        for pack_name, rules in policy_packs.items():
            for rule in rules:
                all_rules.append((pack_name, rule))

        if not all_rules:
            return

        # Scan all source files — read each file ONCE, apply all rules (O(files × rules))
        source_patterns = [
            "*.py",
            "*.js",
            "*.ts",
            "*.jsx",
            "*.tsx",
            "*.go",
            "*.java",
            "*.rb",
            "*.php",
        ]
        scanned = 0

        for pattern in source_patterns:
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                scanned += 1

                # Apply all rules in one pass over this file's content
                for pack_name, rule in all_rules:
                    violations = _check_policy(rule["check"], content, [])
                    for v in violations:
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="policy_violation",
                                severity=Severity(rule["severity"]),
                                file=rel,
                                message=f"[{rule['id']}] {rule['name']}: {v}",
                                cwe=rule["id"],
                                extra={"policy_pack": pack_name},
                            )
                        )

        result.files_scanned = scanned

    def _load_policies(self, inp: AgentInput) -> dict[str, list[dict]]:
        """Load policies from .patchi/policies/ directory, falling back to built-in."""
        policies_dir = inp.root / ".patchi" / "policies"
        custom_policies: dict[str, list[dict]] = {}

        if policies_dir.is_dir():
            for pf in policies_dir.glob("*.yaml"):
                try:
                    data = yaml.safe_load(pf.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and "rules" in data:
                        custom_policies[pf.stem] = data["rules"]
                except Exception as e:
                    _log.warning("PolicyEngineAgent._load_policies failed: %s", e)
            for pf in policies_dir.glob("*.json"):
                try:
                    data = json.loads(pf.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and "rules" in data:
                        custom_policies[pf.stem] = data["rules"]
                except Exception as e:
                    _log.warning("PolicyEngineAgent._load_policies failed: %s", e)

        # Use custom if found, otherwise built-in
        return custom_policies if custom_policies else _BUILTIN_POLICIES
