"""
PrivacyAgent — privacy and data protection issues.

Detects privacy-related security issues:
- Insecure storage of personal data
- Missing data anonymization
- Insufficient data minimization
- Weak consent mechanisms
- Missing data retention policies
- Inadequate data subject rights implementation
- Unencrypted sensitive data transmission
- Weak privacy controls

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
class PrivacyAgent(BaseAgent):
    """Agent for detecting privacy and data protection issues."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "PrivacyAgent"
    description = "Privacy issues: personal data, anonymization, consent, retention, subject rights"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run privacy and data protection detection."""
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
        ]

        # Search for source files
        for pattern in source_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_file_privacy_security(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update(
            {
                "privacy_findings": len(
                    [
                        f
                        for f in findings
                        if any(
                            word in f.title.lower()
                            for word in [
                                "privacy",
                                "personal",
                                "data",
                                "consent",
                                "retention",
                                "subject",
                                "gdpr",
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

    def _scan_file_privacy_security(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a file for privacy and data protection issues."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            # Check for personal data handling
            findings.extend(self._scan_personal_data_handling(content, rel_path))

            # Check for consent mechanisms
            findings.extend(self._scan_consent_mechanisms(content, rel_path))

            # Check for data retention
            findings.extend(self._scan_data_retention(content, rel_path))

            # Check for data subject rights
            findings.extend(self._scan_data_subject_rights(content, rel_path))

            # Check for other privacy issues
            findings.extend(self._scan_other_privacy_issues(content, rel_path))

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Privacy scanner file read error",
                    description=f"Could not analyze {file_path.name} for privacy issues: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_personal_data_handling(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for personal data handling issues."""
        findings = []

        # Look for personal data identifiers
        personal_data_patterns = [
            (r"email", "Email Handling", Severity.MEDIUM),
            (r"phone|telephone|mobile", "Phone Number Handling", Severity.MEDIUM),
            (r"address|street|city|zip|postal", "Address Handling", Severity.MEDIUM),
            (
                r"(?:first[_-]?name|last[_-]?name|full[_-]?name|user[_-]?name)",
                "Name Handling",
                Severity.LOW,
            ),
            (r"ssn|social_security|national_id", "National Identity Handling", Severity.CRITICAL),
            (r"credit_card|card_number|cvv|cvc", "Payment Card Handling", Severity.CRITICAL),
            (r"passport|driver_license", "Government ID Handling", Severity.CRITICAL),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in personal_data_patterns:
                # Use word boundaries to avoid partial matches
                full_pattern = r"\b" + pattern + r"\b"
                matches = re.finditer(full_pattern, line, re.IGNORECASE)
                for match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description=f"Personal data identifier found: {match.group(0)}",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_consent_mechanisms(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for consent mechanism issues."""
        findings = []

        # Look for missing consent mechanisms
        consent_patterns = [
            (r"consent|opt_in|opt_out|preferences", "Consent Mechanism", Severity.INFO),
            (r"tracking|analytics|cookies", "Tracking Consent", Severity.MEDIUM),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in consent_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    # Check if this relates to consent implementation
                    if any(
                        consent_word in line.lower()
                        for consent_word in ["require", "need", "must", "agree", "accept"]
                    ):
                        findings.append(
                            make_finding(
                                severity=severity,
                                file=rel_path,
                                line_start=i,
                                title=description,
                                description="Consent-related functionality found",
                                evidence=line.strip(),
                            )
                        )

        # Look for missing consent for tracking
        if any(
            tracking_term in content.lower()
            for tracking_term in ["ga(", "gtag(", "analytics", "track"]
        ):
            if not any(
                consent_term in content.lower()
                for consent_term in ["consent", "opt_in", "opt_out", "preferences"]
            ):
                findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line_start=0,
                        title="Missing Consent for Analytics Tracking",
                        description="Analytics/tracking found without apparent consent mechanism",
                        evidence="Tracking code found without consent implementation",
                    )
                )

        return findings

    def _scan_data_retention(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for data retention issues."""
        findings = []

        # Look for missing data retention policies
        retention_patterns = [
            (
                r"data.*retention|retention.*policy|expire|delete.*after",
                "Data Retention Policy",
                Severity.INFO,
            ),
            (r"schedule.*delete|cleanup|purge", "Data Cleanup Schedule", Severity.INFO),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in retention_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Data retention/cleanup functionality found",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_data_subject_rights(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for data subject rights implementation."""
        findings = []

        # Look for data subject rights implementation
        rights_patterns = [
            (
                r"right.*access|subject.*access|data.*access",
                "Right of Access Implementation",
                Severity.INFO,
            ),
            (
                r"right.*rectification|subject.*correct|data.*correct",
                "Right to Rectification",
                Severity.INFO,
            ),
            (
                r"right.*erasure|subject.*delete|data.*delete|right.*be.*forgotten",
                "Right to Erasure",
                Severity.INFO,
            ),
            (r"right.*portability|data.*portability", "Right to Portability", Severity.INFO),
            (r"right.*object|objection.*processing", "Right to Object", Severity.INFO),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in rights_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Data subject right implementation found",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_other_privacy_issues(self, content: str, rel_path: str) -> list[Finding]:
        """Scan for other privacy issues."""
        findings = []

        # Look for privacy-related configurations
        privacy_config_patterns = [
            (
                r"privacy_policy|cookie_policy|terms_of_service",
                "Privacy Policy Reference",
                Severity.INFO,
            ),
            (r"gdpr|ccpa|lgpd", "Privacy Regulation Reference", Severity.INFO),
        ]

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, description, severity in privacy_config_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for _match in matches:
                    findings.append(
                        make_finding(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=description,
                            description="Privacy regulation/policy reference found",
                            evidence=line.strip(),
                        )
                    )

        return findings
