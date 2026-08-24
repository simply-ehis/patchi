"""
BanditAgent - Bandit security linter integration.

Bandit is a Python security linter that finds common security issues.
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

_log = logging.getLogger("patchi.security.agents.bandit_agent")


@register
class BanditAgent(BaseAgent):
    """
    BanditAgent - Bandit security linter integration.
    
    Bandit is a Python security linter that finds common security issues
    like SQL injection, XSS, hardcoded passwords, etc.
    """

    group = AgentGroup.SECURITY
    name = "BanditAgent"
    description = "Bandit security linter for Python"
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run Bandit analysis on the project."""
        if not self._is_bandit_available():
            result.status = "SKIPPED"
            result.data["error"] = "Bandit not installed"
            return

        findings = self._run_bandit(inp.root)

        for finding_data in findings:
            finding = self._create_finding(finding_data)
            result.add_finding(finding)

        result.status = "DONE"
        result.files_scanned = 1

    def _is_bandit_available(self) -> bool:
        """Check if Bandit is installed and available."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _run_bandit(self, root: Path) -> List[Dict[str, Any]]:
        """Run Bandit and parse JSON output."""
        findings = []

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "bandit_output.json"

            try:
                result = subprocess.run(
                    [
                        "bandit", "-r",
                        "--format", "json",
                        "--output", str(output_file),
                        str(root)
                    ],
                    capture_output=True,
                    timeout=120,
                    cwd=root
                )

                if output_file.exists():
                    with open(output_file) as f:
                        data = json.load(f)
                        return self._parse_bandit_output(data)

            except subprocess.TimeoutExpired:
                _log.warning("Bandit timed out")
            except Exception as e:
                _log.warning(f"Bandit execution failed: {e}")

        return findings

    def _parse_bandit_output(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Bandit JSON output into findings."""
        findings = []

        for result in data.get("results", []):
            findings.append({
                "type": result.get("test_id", "bandit_finding"),
                "severity": result.get("severity", "MEDIUM").upper(),
                "file": result.get("filename", ""),
                "line": result.get("line_number", 0),
                "message": result.get("issue_text", ""),
                "cwe": result.get("cwe", {}).get("id", ""),
                "confidence": self._map_confidence(result.get("confidence", "MEDIUM")),
            })
        return findings

    def _map_confidence(self, confidence: str) -> float:
        """Map Bandit confidence to float."""
        mapping = {
            "HIGH": 0.9,
            "MEDIUM": 0.6,
            "LOW": 0.3,
        }
        return mapping.get(confidence.upper(), 0.5)

    def _create_finding(self, finding_data: Dict[str, Any]):
        """Create a Finding object from Bandit output."""


        return Finding(
            agent="BanditAgent",
            type=finding_data.get("type", "bandit_finding"),
            severity=Severity(finding_data.get("severity", "MEDIUM")),
            file=finding_data.get("file", ""),
            line=finding_data.get("line", 0),
            message=finding_data.get("message", ""),
            cwe=finding_data.get("cwe", ""),
            confidence=finding_data.get("confidence", 0.5),
        )


# Register the agent
from patchi.core.agents.base import register

register(BanditAgent)
