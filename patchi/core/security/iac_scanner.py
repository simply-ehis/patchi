"""
IaC & Container Security Scanner — Dockerfiles, docker-compose, K8s manifests, Terraform.

Detects:
- Dockerfiles running as root, exposed ports, outdated base images
- docker-compose privileged containers, host network, volume mounts
- Kubernetes missing securityContext, resource limits, network policies
- Terraform public S3, open security groups, unencrypted storage
"""

from __future__ import annotations

import re

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
class IaCScannerAgent(BaseAgent):
    """Scans IaC files for security misconfigurations."""

    name = "IaCScannerAgent"
    group = AgentGroup.SECURITY
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        scanned = 0

        # Dockerfiles
        for fpath in safe_rglob(inp.root, "Dockerfile*"):
            if fpath.is_file():
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                self._scan_dockerfile(content, rel, result)
                scanned += 1

        # docker-compose
        for pattern in [
            "docker-compose*.yml",
            "docker-compose*.yaml",
            "compose.yml",
            "compose.yaml",
        ]:
            for fpath in safe_rglob(inp.root, pattern):
                if fpath.is_file():
                    rel = fpath.relative_to(inp.root).as_posix()
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    self._scan_docker_compose(content, rel, result)
                    scanned += 1

        # K8s manifests
        for pattern in ["*.yaml", "*.yml"]:
            for fpath in safe_rglob(inp.root, pattern):
                if fpath.is_file():
                    rel = fpath.relative_to(inp.root).as_posix()
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        continue
                    if "apiVersion:" in content and ("kind:" in content):
                        self._scan_k8s(content, rel, result)
                        scanned += 1

        # Terraform
        for fpath in safe_rglob(inp.root, "*.tf"):
            if fpath.is_file():
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                self._scan_terraform(content, rel, result)
                scanned += 1

        result.files_scanned = scanned

    def _scan_dockerfile(self, content: str, file: str, result: AgentResult) -> None:
        lines = content.splitlines()
        has_user = False
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if stripped.upper().startswith("USER "):
                has_user = True
                if "root" in stripped.lower():
                    result.add_finding(
                        Finding(
                            agent=self.name,
                            type="container_root",
                            severity=Severity.HIGH,
                            file=file,
                            line=i,
                            message="Container runs as root",
                            cwe="CWE-250",
                        )
                    )
            if stripped.upper().startswith("EXPOSE "):
                ports = stripped.split()[1:]
                for p in ports:
                    if p in ("22", "3389", "6379", "27017", "5432", "3306"):
                        result.add_finding(
                            Finding(
                                agent=self.name,
                                type="exposed_sensitive_port",
                                severity=Severity.MEDIUM,
                                file=file,
                                line=i,
                                message=f"Sensitive port exposed: {p}",
                            )
                        )
            if "latest" in stripped.lower() and stripped.upper().startswith("FROM "):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="latest_base_image",
                        severity=Severity.LOW,
                        file=file,
                        line=i,
                        message="Using 'latest' base image tag — pin to specific version",
                    )
                )
        if not has_user and lines:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="no_user_directive",
                    severity=Severity.MEDIUM,
                    file=file,
                    message="No USER directive — container defaults to root",
                )
            )

    def _scan_docker_compose(self, content: str, file: str, result: AgentResult) -> None:
        if "privileged: true" in content:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="privileged_container",
                    severity=Severity.CRITICAL,
                    file=file,
                    message="Privileged container detected",
                    cwe="CWE-250",
                )
            )
        if "network_mode: host" in content:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="host_network",
                    severity=Severity.HIGH,
                    file=file,
                    message="Host network mode — container shares host network stack",
                )
            )
        if re.search(r'"/etc:/etc"', content) or re.search(r'"/var/run/docker.sock"', content):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="dangerous_volume_mount",
                    severity=Severity.CRITICAL,
                    file=file,
                    message="Dangerous volume mount (host system path or Docker socket)",
                    cwe="CWE-250",
                )
            )

    def _scan_k8s(self, content: str, file: str, result: AgentResult) -> None:
        if "kind: Deployment" in content or "kind: StatefulSet" in content:
            if "securityContext" not in content:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="missing_security_context",
                        severity=Severity.HIGH,
                        file=file,
                        message="K8s workload missing securityContext",
                        cwe="CWE-250",
                    )
                )
            if "resources:" not in content:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="missing_resource_limits",
                        severity=Severity.MEDIUM,
                        file=file,
                        message="K8s workload missing resource limits",
                    )
                )
        if "kind: NetworkPolicy" not in content and "kind: Deployment" in content:
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="no_network_policy",
                    severity=Severity.LOW,
                    file=file,
                    message="No NetworkPolicy found — all pod-to-pod traffic allowed",
                )
            )

    def _scan_terraform(self, content: str, file: str, result: AgentResult) -> None:
        if re.search(r'acl\s*=\s*"public"', content, re.I):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="public_s3_bucket",
                    severity=Severity.CRITICAL,
                    file=file,
                    message="S3 bucket with public ACL",
                    cwe="CWE-200",
                )
            )
        if re.search(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]', content):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="open_security_group",
                    severity=Severity.HIGH,
                    file=file,
                    message="Security group open to 0.0.0.0/0",
                    cwe="CWE-284",
                )
            )
        if re.search(r"encrypt\s*=\s*false", content, re.I):
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="unencrypted_storage",
                    severity=Severity.HIGH,
                    file=file,
                    message="Unencrypted storage resource",
                    cwe="CWE-311",
                )
            )
