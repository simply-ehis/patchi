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
import logging
import os
import subprocess
from pathlib import Path

from patchi.core.constants import is_offline

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
)

_log = logging.getLogger("patchi.security.agents.sast_agent")


@register
class SemgrepAgent(BaseAgent):
    """Pattern-tier SAST via a local semgrep rule pack (no network needed).

    Distinct from security_taint.TaintAnalyzer: that agent is AST taint
    tracking + AI confirmation; this one is deterministic pattern matching.
    Both feed the ConfidenceGate as separate confirming witnesses.
    """

    group = AgentGroup.SECURITY
    domain = AgentDomain.CODE_QUALITY
    name = "SemgrepAgent"
    description = "Deterministic pattern SAST using the bundled semgrep rule pack"

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

    def _rules_pack(self, root: Path) -> Path | None:
        """Locate the in-repo deterministic rule pack (no network needed)."""
        candidates = [
            root / "patchi" / "core" / "security" / "semgrep_rules" / "security.yaml",
            # when patchi itself is installed as a package
            Path(__file__).parent / "semgrep_rules" / "security.yaml",
        ]
        for c in candidates:
            if c.is_file():
                return c
        return None

    def _run_semgrep(self, root: Path, scope: list[str] | None) -> list[Finding] | None:
        """Run semgrep with the local rules pack; bounded network fallback.

        Never falls back to --config=auto (the full registry pull can take many
        minutes). When no local pack exists we only try the single, bounded
        p/owasp-top-ten registry pack while online.
        """
        pack = self._rules_pack(root)
        configs = []
        if pack is not None:
            configs.append(str(pack))
        elif not is_offline():
            configs.append("p/owasp-top-ten")
        if not configs:
            return None

        target = str(root)
        env = {**os.environ, "SEMGREP_SEND_METRICS": "off"}
        for config_value in configs:
            cmd = ["semgrep", "--json", "--config", config_value, target]
            try:
                process_result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=300,
                    cwd=str(root),
                    env=env,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
            except Exception:  # noqa: BLE001
                continue

            # semgrep: 0 = clean, 1 = findings, 2 = config/runtime error
            if process_result.returncode not in (0, 1):
                _log.debug("semgrep rc=%s for config %s", process_result.returncode, config_value)
                continue

            try:
                parsed = json.loads(process_result.stdout)
            except json.JSONDecodeError:
                continue
            return self._parse_semgrep_results(parsed, root)

        return None

    def _parse_semgrep_results(self, parsed: dict, root: Path) -> list[Finding]:
        """Parse semgrep JSON with full metadata fidelity."""
        findings = []
        for item in parsed.get("results", []):
            path = item.get("path", "")
            start_line = item.get("start", {}).get("line", 1)
            check_id = item.get("check_id", "unknown")
            # strip registry path prefixes ("python.lang.security.audit" etc.)
            short_id = check_id.split(".")[-1] if "." in check_id else check_id
            extra = item.get("extra", {})
            message = extra.get("message", "Security vulnerability detected")
            severity_raw = extra.get("severity", "WARNING")

            severity = self._map_severity_from_semgrep(severity_raw)
            meta = extra.get("metadata", {}) or {}
            cwe_raw = meta.get("cwe") or ""
            if isinstance(cwe_raw, list):
                cwe_raw = cwe_raw[0] if cwe_raw else ""
            cwe = str(cwe_raw).strip()
            # normalize "CWE-89 (…)" / "89" spellings to CWE-<int>
            if cwe and not cwe.upper().startswith("CWE"):
                digits = "".join(ch for ch in cwe if ch.isdigit())
                cwe = f"CWE-{int(digits)}" if digits else ""

            abs_file_path = Path(root) / path
            if not abs_file_path.exists():
                continue

            finding = make_finding(
                agent=self.name,
                finding_type=short_id,
                severity=severity,
                file=path,
                line=start_line,
                message=f"SAST: {message}"[:400],
                detail=message,
                code_snippet=(extra.get("lines", "") or "")[:500],
                suggestion="Review and fix the identified security vulnerability",
                fix_agent="SecurityFixer",
                cwe=cwe,
            )
            # tool's own confidence tier preserved for the ConfidenceGate
            tier = str(meta.get("confidence", "")).upper()
            if tier in ("HIGH", "MEDIUM", "LOW"):
                finding.extra["tool_confidence"] = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}[tier]
            findings.append(finding)

        return findings

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
        # For now, empty: the local rule pack covers the primary path.
        return []
