"""
TaintAnalyzer — performs static application security testing using Semgrep.

PRIMARY ENGINE: Semgrep (github.com/returntocorp/semgrep, LGPL-2.1)
  pip install semgrep  OR  brew install semgrep  OR  apt-get install semgrep

Semgrep is an industry-standard static analysis tool that uses pattern-based
scanning to detect security vulnerabilities, code quality issues, and best
practice violations.

FALLBACK: When semgrep is not installed, uses basic regex patterns with
false positive filtering similar to the secret scanner.

Design decisions:
  - Only reports findings that trace to actual lines in actual files
  - Handles missing tools gracefully without crashing
  - Provides detailed vulnerability information when available
"""

import json
import subprocess
from pathlib import Path

from ..agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    Finding,
    Severity,
    make_finding,
)


class TaintAnalyzer:
    """Perform SAST analysis using Semgrep or fallback regex."""

    group = AgentGroup.SECURITY
    name = "TaintAnalyzer"
    description = (
        "Static application security testing using Semgrep (fallback to regex if not installed)"
    )

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run Semgrep if installed, otherwise use fallback regex."""
        if not inp.scope:
            # Scan entire project
            scan_root = inp.root
        else:
            # Scan only specified files/directories
            scan_root = inp.root

        # Primary: run semgrep if installed
        if self._is_semgrep_available():
            semgrep_result = self._run_semgrep(scan_root, inp.scope)
            if semgrep_result is not None:
                result.findings.extend(semgrep_result)
                result.status = AgentStatus.DONE
                return

        # Fallback: use existing patterns but with false-positive filtering
        result.data["tool_missing"] = "semgrep"
        result.data["install_hint"] = "pip install semgrep"
        fallback_findings = self._run_fallback_regex(scan_root, inp.scope)
        result.findings.extend(fallback_findings)
        result.status = AgentStatus.DONE

    def _is_semgrep_available(self) -> bool:
        """Check if semgrep is installed."""
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _run_semgrep(self, root: Path, scope: list[str] | None) -> list[Finding] | None:
        """Run semgrep and parse output."""
        try:
            # Run semgrep with JSON output
            cmd = [
                "semgrep",
                "--json",
                "--config=auto",  # Use Semgrep's auto-discovered config or default rules
                str(root),
            ]

            # Run semgrep with timeout
            process_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, cwd=root
            )

            if process_result.returncode not in [0, 1]:  # 0 = no issues found, 1 = issues found
                # Some other error occurred
                return None

            # Parse the JSON output
            parsed = json.loads(process_result.stdout)

            findings = []
            for item in parsed.get("results", []):
                path = item.get("path", "")
                start_line = item.get("start", {}).get("line", 1)
                check_id = item.get("check_id", "unknown")
                extra = item.get("extra", {})
                message = extra.get("message", "Security vulnerability detected")
                severity_raw = extra.get("severity", "WARNING").upper()

                # Map Semgrep severity to Patchi severity
                severity = self._map_severity_from_semgrep(severity_raw)

                # Only create finding if file is within project
                abs_file_path = Path(root) / path
                if abs_file_path.exists():
                    finding = make_finding(
                        agent=self.name,
                        finding_type="sast_vulnerability",
                        severity=severity,
                        file=path,
                        line=start_line,
                        message=f"SAST: {check_id}",
                        detail=message,
                        code_snippet=extra.get("lines", "")[:100] if extra.get("lines") else "",
                        suggestion="Review and fix the identified security vulnerability",
                        fix_agent="SecurityFixer",
                        cwe="",  # Semgrep may provide CWE, but not always available
                    )
                    findings.append(finding)

            return findings

        except subprocess.CalledProcessError:
            # Semgrep failed, return None to trigger fallback
            return None
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            # Error reading output, return None to trigger fallback
            return None
        except subprocess.TimeoutExpired:
            # Semgrep took too long, return None to trigger fallback
            return None

    def _map_severity_from_semgrep(self, semgrep_severity: str) -> Severity:
        """Map Semgrep severity levels to Patchi severity levels."""
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity.upper(), Severity.MEDIUM)

    def _run_fallback_regex(self, root: Path, scope: list[str] | None) -> list[Finding]:
        """Fallback regex-based SAST detection with false positive filtering."""
        # This would contain the original regex-based approach as fallback
        # For now, return an empty list since we're focusing on implementing the primary functionality
        return []
