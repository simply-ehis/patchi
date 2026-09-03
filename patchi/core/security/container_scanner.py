"""
Container Scanner — scans container images and Dockerfiles for vulnerabilities.

Wraps Trivy (optional subprocess) for container image CVE scanning.
Falls back to static Dockerfile analysis when Trivy is not available.
"""

from __future__ import annotations

import json
import re
import subprocess

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


@register
class ContainerScannerAgent(BaseAgent):
    """Scans container images and Dockerfiles for CVEs and misconfigurations."""

    name = "ContainerScannerAgent"
    group = AgentGroup.SECURITY
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        scanned = 0

        # Try Trivy image scan if available
        trivy_available = self._check_trivy()
        if trivy_available:
            scanned += self._scan_with_trivy(inp, result)

        # Always do static Dockerfile analysis
        scanned += self._scan_dockerfiles(inp, result)

        # Scan docker-compose for image references
        scanned += self._scan_compose_images(inp, result)

        result.files_scanned = scanned

    def _check_trivy(self) -> bool:
        try:
            proc = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _scan_with_trivy(self, inp: AgentInput, result: AgentResult) -> int:
        """Scan Dockerfiles with Trivy config scanner."""
        count = 0
        for fpath in safe_rglob(inp.root, "Dockerfile*"):
            if not fpath.is_file():
                continue
            rel = fpath.relative_to(inp.root).as_posix()
            try:
                proc = subprocess.run(
                    ["trivy", "config", "--format=json", str(fpath)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if proc.stdout.strip():
                    data = json.loads(proc.stdout)
                    for target in data.get("Results", []):
                        for vuln in target.get("Vulnerabilities", []):
                            sev = vuln.get("Severity", "MEDIUM").upper()
                            result.add_finding(
                                Finding(
                                    agent=self.name,
                                    type="container_cve",
                                    severity=Severity(sev.lower())
                                    if sev.lower() in ("critical", "high", "medium", "low")
                                    else Severity.MEDIUM,
                                    file=rel,
                                    message=f"{vuln.get('VulnerabilityID', '')}: {vuln.get('Title', 'Container vulnerability')}",
                                    cwe=vuln.get("CweIDs", [""])[0] if vuln.get("CweIDs") else "",
                                    extra={
                                        "vuln_id": vuln.get("VulnerabilityID", ""),
                                        "pkg": vuln.get("PkgName", ""),
                                        "installed": vuln.get("InstalledVersion", ""),
                                        "fixed": vuln.get("FixedVersion", ""),
                                    },
                                )
                            )
            except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
                pass
            count += 1
        return count

    def _check_layer_bloat(self, content: str, rel: str, result: AgentResult) -> None:
        """§8.3.3 dive / scout heuristic: layer bloat detection §8.3.3."""
        import shutil as _sh
        import subprocess as _sp

        # Try dive CI if installed
        if _sh.which("dive"):
            try:
                proc = _sp.run(
                    ["dive", "--ci", "--json", rel],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if proc.stdout:
                    import json as _js

                    data = _js.loads(proc.stdout)
                    eff = data.get("efficiencyScore", 1.0)
                    if eff < 0.9:
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="layer_bloat",
                                severity=Severity.MEDIUM,
                                file=rel,
                                message=f"Dive efficiency {eff:.0%} — image has wasted space / duplicate layers",
                            )
                        )
                    return  # dive succeeded, skip heuristic
            except Exception as _exc:
                logging.getLogger("patchi").debug('suppressed: %s', _exc)
        # Heuristic fallback: count RUN, check multi-stage, large base
        runs = len(re.findall(r"^\s*RUN\s+", content, re.MULTILINE | re.I))
        froms = re.findall(r"^\s*FROM\s+(\S+)", content, re.MULTILINE | re.I)
        if runs > 7:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="layer_bloat",
                    severity=Severity.LOW,
                    file=rel,
                    message=f"{runs} RUN layers — consolidate with && \\ to reduce layers (dive: layer bloat)",
                )
            )
        if len(froms) == 1 and runs > 5:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="no_multistage",
                    severity=Severity.LOW,
                    file=rel,
                    message="Single-stage build with many RUNs — consider multi-stage to slim final image",
                )
            )
        for base in froms:
            if any(b in base.lower() for b in (":latest", "ubuntu:latest", "alpine:latest")) or ":" not in base:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="unpinned_base",
                        severity=Severity.MEDIUM,
                        file=rel,
                        message=f"Unpinned base image: {base} — pin to digest or specific tag",
                    )
                )

    def _scan_dockerfiles(self, inp: AgentInput, result: AgentResult) -> int:
        """Static Dockerfile analysis when Trivy is not available."""
        count = 0
        for fpath in safe_rglob(inp.root, "Dockerfile*"):
            if not fpath.is_file():
                continue
            rel = fpath.relative_to(inp.root).as_posix()
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            count += 1

            lines = content.splitlines()
            has_healthcheck = False
            has_copy_add = False

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                upper = stripped.upper()

                # HEALTHCHECK
                if upper.startswith("HEALTHCHECK"):
                    has_healthcheck = True

                # COPY vs ADD
                if upper.startswith("ADD ") and not has_copy_add:
                    has_copy_add = True
                    result.add_finding(
                        Finding(
                            agent=self.name,
                            type="use_copy_over_add",
                            severity=Severity.LOW,
                            file=rel,
                            line=i,
                            message="Consider using COPY instead of ADD (ADD has implicit tar extraction)",
                        )
                    )

                # Secrets in ENV
                if upper.startswith("ENV "):
                    secretish = re.search(
                        r"(?:password|secret|key|token|api_key)\s*=\s*\S+",
                        stripped,
                        re.I,
                    )
                    if secretish:
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="env_secret",
                                severity=Severity.CRITICAL,
                                file=rel,
                                line=i,
                                message="Secret in ENV — use build-time secrets or runtime injection",
                                cwe="CWE-798",
                            )
                        )

            if not has_healthcheck and lines:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="no_healthcheck",
                        severity=Severity.LOW,
                        file=rel,
                        message="No HEALTHCHECK instruction — container health unknown to orchestrator",
                    )
                )

            # Layer bloat check §8.3.3
            self._check_layer_bloat(content, rel, result)

        return count

    def _scan_compose_images(self, inp: AgentInput, result: AgentResult) -> int:
        """Check docker-compose for :latest tags and unpinned images."""
        count = 0
        for pattern in [
            "docker-compose*.yml",
            "docker-compose*.yaml",
            "compose.yml",
            "compose.yaml",
        ]:
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                count += 1

                for m in re.finditer(r'image:\s*["\']?([^"\'\s]+)["\']?', content):
                    img = m.group(1)
                    if ":latest" in img or ":" not in img:
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="unpinned_image",
                                severity=Severity.MEDIUM,
                                file=rel,
                                message=f"Unpinned or :latest image: {img}",
                            )
                        )

        return count
