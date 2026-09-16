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
from typing import Any

from patchi.core.agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
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
    domain = AgentDomain.SECURITY
    name = "CodeqlAgent"
    description = "CodeQL semantic analysis for vulnerabilities"
    # Database build + QL compilation is genuinely slow (minutes even on tiny
    # projects the first time). The old 180s timeout guaranteed silent zeros.
    timeout = 3600

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run CodeQL analysis on the project."""
        if not self._is_codeql_available():
            self.skip_for_tool(result, "codeql")
            return

        self.skip_python_sources = False
        findings = self._run_codeql(inp.root)

        if getattr(self, "skip_python_sources", False):
            result.data["skip_reason"] = "no Python sources in repo — codeql python suite has nothing to analyze"
            result.status = AgentStatus.SKIPPED
            return

        for finding_data in findings:
            finding = self._create_finding(finding_data)
            result.add_finding(finding)

        result.status = AgentStatus.DONE
        result.files_scanned = 1

    def _is_codeql_available(self) -> bool:
        """Check if CodeQL CLI is installed and available."""
        try:
            result = subprocess.run(["codeql", "version"], capture_output=True, timeout=10)
            return result.returncode == 0
        except FileNotFoundError:
            return False

    def _resolve_query_suite(self) -> str:
        """Prefer a locally cached query pack; never hit the network.

        ``--download``/bare pack names trip a CLI pack-manifest bug
        (UnrecognizedPropertyException on Docker digest) and need network.
        The standard install caches packs under ~/.codeql/packages.
        """
        candidates = sorted(
            (Path.home() / ".codeql" / "packages" / "codeql" / "python-queries").glob(
                "*/codeql-suites/python-security-extended.qls"
            )
        )
        if candidates:
            return str(candidates[-1])
        return "python-security-extended"

    def _has_python_sources(self, root: Path) -> bool:
        """True if the repo actually contains Python code to build a DB from."""
        try:
            for p in root.rglob("*.py"):
                rel = p.relative_to(root)
                parts = {seg.lower() for seg in rel.parts}
                if parts & {"node_modules", ".venv", "venv", ".git", "dist", "build"}:
                    continue
                return True
        except OSError:
            return True  # can't tell — let codeql try rather than skip
        return False

    def _run_codeql(self, root: Path) -> list[dict[str, Any]]:
        """Create a database, run the security suite, return parsed findings."""
        findings: list[dict[str, Any]] = []
        suite = self._resolve_query_suite()

        # A Python-only database create on a repo without Python entry
        # points dies inside autobuild ("Exit status 4 from runner.exe") —
        # that is the tool refusing the job, not a transient error. Detect
        # it up front and skip honestly instead of logging a red-herring
        # tool crash on every non-Python scan.
        if not self._has_python_sources(root):
            self.skip_python_sources = True
            _log.info("CodeQL: no Python sources under %s — skipping (nothing to build)", root)
            return findings

        with tempfile.TemporaryDirectory() as tmpdir:
            db_dir = Path(tmpdir) / "codeql_db"
            results_file = Path(tmpdir) / "results.sarif"

            try:
                # ── Phase 1: database create ────────────────────────────────
                result = subprocess.run(
                    [
                        "codeql",
                        "database",
                        "create",
                        str(db_dir),
                        "--language=python",
                        "--source-root",
                        str(root),
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=900,
                    cwd=str(root),
                )

                if result.returncode != 0:
                    tail = (result.stderr or result.stdout or "")[-300:]
                    _log.warning("CodeQL database creation failed: %s", tail)
                    return findings

                # ── Phase 2: analyze against the security suite ─────────────
                result = subprocess.run(
                    [
                        "codeql",
                        "database",
                        "analyze",
                        str(db_dir),
                        suite,
                        "--format=sarif-latest",
                        "--output",
                        str(results_file),
                        "--sarif-add-snippets",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=3600,
                    cwd=str(root),
                )

                if result.returncode != 0:
                    tail = (result.stderr or result.stdout or "")[-300:]
                    _log.warning("CodeQL analyze failed: %s", tail)
                    return findings

                if results_file.exists():
                    with open(results_file, encoding="utf-8") as f:
                        data = json.load(f)
                        return self._parse_sarif_output(data)

            except subprocess.TimeoutExpired:
                _log.warning("CodeQL timed out")
            except Exception as e:  # noqa: BLE001 — tool failures are data
                _log.warning("CodeQL execution failed: %s", e)

        return findings

    def _parse_sarif_output(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse SARIF into finding dicts with full fidelity.

        Extracts per-rule metadata (CWE tags, numeric security-severity)
        and per-result code snippets so downstream scoring and AI review
        get real context instead of bare rule ids.
        """
        findings: list[dict[str, Any]] = []

        for run in data.get("runs", []):
            # Rule metadata lives in tool.driver.rules / extensions
            rules_by_id: dict[str, dict[str, Any]] = {}
            for tool in run.get("tool", {}).get("driver", {}).get("rules", []) + [
                r for ext in run.get("tool", {}).get("extensions", []) for r in ext.get("rules", [])
            ]:
                rid = tool.get("id", "")
                if rid:
                    rules_by_id[rid] = tool

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "codeql_finding")
                rule_meta = rules_by_id.get(rule_id, {})
                props = rule_meta.get("properties", {}) or {}

                # Severity: prefer numeric security-severity (0-10)
                sec_sev = props.get("security-severity")
                level = result.get("level") or props.get("problem.severity") or "warning"

                # CWE from tags like "security/cwe/cwe-089"
                cwe = ""
                for tag in props.get("tags", []) or []:
                    tag_l = str(tag).lower()
                    if "cwe-" in tag_l:
                        idx = tag_l.index("cwe-")
                        num = "".join(ch for ch in tag_l[idx + 4 :] if ch.isdigit())
                        if num:
                            cwe = f"CWE-{int(num)}"
                            break

                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                artifact = location.get("artifactLocation", {})
                region = location.get("region", {})
                snippet = (region.get("snippet", {}) or {}).get("text", "")

                findings.append(
                    {
                        "type": rule_id,
                        "severity": sec_sev if sec_sev is not None else level,
                        "file": artifact.get("uri", ""),
                        "line": region.get("startLine", 0),
                        "message": (result.get("message", {}) or {}).get("text", ""),
                        "cwe": cwe,
                        "snippet": snippet,
                        "rule_id": rule_id,
                    }
                )
        return findings

    def _create_finding(self, finding_data: dict[str, Any]):
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
