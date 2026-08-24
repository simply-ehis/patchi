"""
PysaAgent - Python Static Analyzer integration.

Pysa (Python Static Analyzer) is a static analysis tool for Python that focuses on
security vulnerabilities like SQL injection, XSS, and other taint-style vulnerabilities.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)

_log = logging.getLogger("patchi.security.agents.pysa_agent")


@register
class PysaAgent(BaseAgent):
    """
    PysaAgent - Python Static Analyzer integration.
    
    Pysa is a static analysis tool for Python that focuses on security vulnerabilities
    through taint analysis. It tracks data flow from sources to sinks.
    """

    group = AgentGroup.SECURITY
    name = "PysaAgent"
    description = "Pysa static analyzer for Python security vulnerabilities"
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run Pysa analysis on the project."""
        if not self._is_pysa_available():
            result.status = "SKIPPED"
            result.data["error"] = "Pysa not installed"
            return

        findings = self._run_pysa(inp.root)

        for finding_data in findings:
            finding = self._create_finding(finding_data)
            result.add_finding(finding)

        result.status = "DONE"
        result.files_scanned = 1

    def _is_pysa_available(self) -> bool:
        """Check if Pysa is installed and available."""
        try:
            result = subprocess.run(
                ["pysa", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _run_pysa(self, root: Path) -> List[Dict[str, Any]]:
        """Run Pysa and parse JSON output."""
        findings = []

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "pysa_output.json"

            try:
                result = subprocess.run(
                    [
                        "pysa", "analyze",
                        "--output-format", "json",
                        "--output", str(tmpdir / "pysa_output"),
                        str(root)
                    ],
                    capture_output=True,
                    timeout=120,
                    cwd=root
                )

                # Parse Pysa JSON output
                output_dir = Path(tmpdir) / "pysa_output"
                if output_dir.exists():
                    for json_file in output_dir.glob("*.json"):
                        with open(json_file) as f:
                            data = json.load(f)
                            findings.extend(self._parse_pysa_output(data))

            except subprocess.TimeoutExpired:
                _log.warning("Pysa timed out")
            except Exception as e:
                _log.warning(f"Pysa execution failed: {e}")

        return findings

    def _parse_pysa_output(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Pysa JSON output into findings."""
        findings = []

        for issue in data.get("issues", []):
            findings.append({
                "type": issue.get("code", "pysa_finding"),
                "severity": issue.get("severity", "MEDIUM").upper(),
                "file": issue.get("file", ""),
                "line": issue.get("line", 0),
                "message": issue.get("message", ""),
                "cwe": issue.get("cwe", ""),
                "confidence": 0.8,
            })
        return findings

    def _create_finding(self, finding_data: Dict[str, Any]):
        """Create a Finding object from Pysa output."""


        return Finding(
            agent="PysaAgent",
            type=finding_data.get("type", "pysa_finding"),
            severity=Severity(finding_data.get("severity", "MEDIUM")),
            file=finding_data.get("file", ""),
            line=finding_data.get("line", 0),
            message=finding_data.get("message", ""),
            cwe=finding_data.get("cwe", ""),
            confidence=0.8,
        )


# Register the agent
from patchi.core.agents.base import register

register(PysaAgent)
