"""
ComplianceAgent — regulatory compliance issues.

Detects compliance-related security issues:
- PCI DSS violations
- HIPAA violations
- GDPR violations
- SOX compliance issues
- Industry-specific regulations
- Audit trail requirements
- Logging requirements
- Access controls for compliance

Uses pattern matching and code analysis.
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
)


@register
class ComplianceAgent(BaseAgent):
    """Agent for detecting regulatory compliance issues."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "ComplianceAgent"
    description = "Compliance issues: PCI DSS, HIPAA, GDPR, SOX, audit trails, access controls"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run compliance detection."""
        findings = []

        # Define source file patterns to scan
        source_patterns = [
            "*.py",
            "*.js",
            "*.jsx",
            "*.ts",
            "*.tsx",
            "*.java",
            "*.php",
            "*.rb",
            "*.go",
            "*.rs",
            "*.cpp",
            "*.cxx",
            "*.cc",
            "*.c",
            "*.h",
            "*.hpp",
            "*.cs",
            "*.json",
            "*.yml",
            "*.yaml",
            "*.xml",
            "**/config/**",
            "**/settings/**",
            "**/policy/**",
            "**/compliance/**",
        ]

        # Search for source files
        for pattern in source_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_file_compliance_security(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "compliance_findings": len(
                    [
                        f
                        for f in findings
                        if any(
                            word in f.title.lower()
                            for word in [
                                "compliance",
                                "pci",
                                "hipaa",
                                "gdpr",
                                "sox",
                                "audit",
                                "logging",
                                "access",
                            ]
                        )
                    ]
                ),
                "needs_ai": False,
            }
        )
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        from pathlib import PurePosixPath

        # Check restrictions
        restrictions = inp.config.get("restrictions", [])
        for r in restrictions:
            if r.get("enabled", True):
                path = r["path"]
                if file_path.startswith(path) or PurePosixPath(file_path).match(path):
                    if r["type"] == "NO_TOUCH":
                        return True
                    elif r["type"] == "SCAN_ONLY" and self.__class__.__name__ == "FixAgent":
                        return True
        return False

    def _scan_file_compliance_security(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a file for compliance issues."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            # Check for compliance regulation references
            findings.extend(self._scan_compliance_regulations(content, rel_path))

            # Check for audit trail requirements
            findings.extend(self._scan_audit_trails(content, rel_path))

            # Check for logging requirements
            findings.extend(self._scan_logging_requirements(content, rel_path))

            # Check for access controls
            findings.extend(self._scan_access_controls(content, rel_path))

            # Check for other compliance issues
            findings.extend(self._scan_other_compliance_issues(content, rel_path))

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Compliance scanner file read error",
                    description=f"Could not analyze {file_path.name} for compliance issues: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_compliance_regulations(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for compliance regulation references."""
        findings = []

        # Look for compliance regulation references
        compliance_patterns = [
            (r"PCI\s*DSS|PCI_DSS|payment card industry", "PCI DSS Compliance", Severity.INFO),
            (r"HIPAA|health insurance portability", "HIPAA Compliance", Severity.INFO),
            (r"GDPR|general data protection regulation", "GDPR Compliance", Severity.INFO),
            (r"SOX|sarbanes\s*oxley|public company accounting", "SOX Compliance", Severity.INFO),
            (r"CCPA|california consumer privacy", "CCPA Compliance", Severity.INFO),
            (
                r"GLBA|gramm\s*leach\s*bliley|financial services modernization",
                "GLBA Compliance",
                Severity.INFO,
            ),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in compliance_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Compliance regulation reference found",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_audit_trails(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for audit trail requirements."""
        findings = []

        # Look for audit trail implementation
        audit_patterns = [
            (
                r"audit|audit_log|audit_trail|change_log",
                "Audit Trail Implementation",
                Severity.INFO,
            ),
            (r"log.*action|record.*action|track.*action", "Action Logging", Severity.INFO),
            (r"user.*activity|activity.*log|event.*log", "Activity Logging", Severity.INFO),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in audit_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Audit trail/logging functionality found",
                            evidence=line.strip(),
                        )
                    )

        # Check for missing audit trails where they should be present
        sensitive_operations = ["delete", "update", "modify", "remove", "transfer", "share"]
        for op in sensitive_operations:
            if op in content.lower():
                has_audit = any(
                    audit_term in content.lower()
                    for audit_term in ["audit", "log", "track", "record"]
                )
                if not has_audit:
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            line_start=0,
                            title=f"Missing Audit Trail for {op.title()} Operation",
                            description=f"Sensitivity operation '{op}' found without apparent audit trail",
                            evidence=f"Sensitivity operation '{op}' without audit logging",
                        )
                    )

        return findings

    def _scan_logging_requirements(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for logging requirements."""
        findings = []

        # Look for logging implementation
        logging_patterns = [
            (r"log|logging|logger", "Logging Implementation", Severity.INFO),
            (r"error.*log|exception.*log|warning.*log", "Error Logging", Severity.INFO),
            (r"security.*log|auth.*log|access.*log", "Security Logging", Severity.INFO),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in logging_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Logging functionality found",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_access_controls(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for access control requirements."""
        findings = []

        # Look for access control implementation
        access_control_patterns = [
            (
                r"permission|authorization|authz|acl|role.*based|rbac",
                "Access Control Implementation",
                Severity.INFO,
            ),
            (r"admin|administrator|superuser|root", "Privileged Access", Severity.INFO),
            (r"privilege|elevat|escalat", "Privilege Management", Severity.INFO),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in access_control_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Access control functionality found",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_other_compliance_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for other compliance issues."""
        findings = []

        # Look for compliance-related configurations
        compliance_config_patterns = [
            (r"compliance|regulation|standard", "Compliance Configuration", Severity.INFO),
            (r"policy|procedure|control", "Policy/Procedure Reference", Severity.INFO),
            (r"certificat|audit|review", "Audit/Certification Reference", Severity.INFO),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in compliance_config_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Compliance-related configuration found",
                            evidence=line.strip(),
                        )
                    )

        return findings
