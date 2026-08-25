"""
CodeQLAgent - CodeQL static analysis integration.

CodeQL is a semantic code analysis engine from GitHub that can find
vulnerabilities and code quality issues.
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

_log = logging.getLogger("patchi.security.agents.codeql_agent")


@register
class CodeqlAgent(BaseAgent):
    """
    CodeQLAgent - CodeQL static analysis integration.
    
    CodeQL is a semantic code analysis engine from GitHub that can find
    vulnerabilities and code quality issues using a query-based approach.
    """

    group = AgentGroup.SECURITY
    name = "CodeqlAgent"
    description = "CodeQL semantic analysis for vulnerabilities"
    timeout = 180

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run CodeQL analysis on the project."""
        if not self._is_codeql_available():
            result.status = "SKIPPED"
            result.data["error"] = "CodeQL CLI not installed"
            return

        findings = self._run_codeql(inp.root)

        for finding_data in findings:
            finding = self._create_finding(finding_data)
            result.add_finding(finding)

        result.status = "DONE"
        result.files_scanned = 1

    def _is_codeql_available(self) -> bool:
        """Check if CodeQL CLI is installed and available."""
        try:
            result = subprocess.run(
                ["codeql", "version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _run_codeql(self, root: Path) -> List[Dict[str, Any]]:
        """Run CodeQL analysis and parse results."""
        findings = []

        with tempfile.TemporaryDirectory() as tmpdir:
            db_dir = Path(tmpdir) / "codeql_db"
            results_file = Path(tmpdir) / "results.sarif"

            try:
                # Create database
                result = subprocess.run(
                    ["codeql", "database", "create", str(db_dir), "--language=python", "--source-root", str(root)],
                    capture_output=True,
                    timeout=180,
                    cwd=root
                )

                if result.returncode != 0:
                    _log.warning(f"CodeQL database creation failed: {result.stderr.decode()}")
                    return findings

                # Run queries
                result = subprocess.run(
                    [
                        "codeql", "database", "analyze", str(db_dir),
                        "--format=sarif-latest",
                        "--output", str(results_file),
                        "python-security-extended"
                    ],
                    capture_output=True,
                    timeout=180,
                    cwd=root
                )

                if results_file.exists():
                    with open(results_file) as f:
                        data = json.load(f)
                        return self._parse_sarif_output(data)

            except subprocess.TimeoutExpired:
                _log.warning("CodeQL timed out")
            except Exception as e:
                _log.warning(f"CodeQL execution failed: {e}")

        return findings

    def _parse_sarif_output(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse SARIF output into findings."""
        findings = []

        for run in data.get("runs", []):
            for result in run.get("results", []):
                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                artifact = location.get("artifactLocation", {})

                findings.append({
                    "type": result.get("ruleId", "codeql_finding"),
                    "severity": result.get("level", "warning").upper(),
                    "file": artifact.get("uri", ""),
                    "line": location.get("region", {}).get("startLine", 0),
                    "message": result.get("message", {}).get("text", ""),
                    "cwe": "",
                    "confidence": 0.8,
                })
        return findings

    def _create_finding(self, finding_data: Dict[str, Any]):
        """Create a Finding object from CodeQL output."""
        from patchi.core.security.tool_adapters import make_tool_finding

        return make_tool_finding(
            agent="CodeqlAgent",
            ftype=finding_data.get("type", "codeql_finding"),
            raw_severity=finding_data.get("severity", "MEDIUM"),
            file=finding_data.get("file", ""),
            line=finding_data.get("line", 0),
            message=finding_data.get("message", ""),
            cwe=finding_data.get("cwe", ""),
            snippet=finding_data.get("snippet", ""),
            confidence_raw=0.8,  # database-query findings: semantic, not pattern
            extra={"rule_id": finding_data.get("rule_id", "")},
        )


# Register the agent
from patchi.core.agents.base import register

register(CodeqlAgent)
