"""Service mesh security agent — validates Istio/Linkerd mesh configuration."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from ..agents.base import (
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
from ..brain.trace_log import trace_agent

# Istio CRD patterns
ISTIO_CRDS = {
    "VirtualService": {
        "kind": r"kind:\s*VirtualService",
        "hosts": r"hosts:",
        "http": r"http:",
        "route": r"route:",
        "tls": r"tls:",
    },
    "DestinationRule": {
        "kind": r"kind:\s*DestinationRule",
        "mtls": r"mtls:",
        "tls": r"tls:",
        "traffic_policy": r"trafficPolicy:",
        "connection_pool": r"connectionPool:",
    },
    "PeerAuthentication": {
        "kind": r"kind:\s*PeerAuthentication",
        "mtls": r"mtls:",
        "strict": r"STRICT|mode:\s*STRICT",
        "permissive": r"PERMISSIVE|mode:\s*PERMISSIVE",
    },
    "AuthorizationPolicy": {
        "kind": r"kind:\s*AuthorizationPolicy",
        "rules": r"rules:",
        "action": r"action:",
        "deny": r"DENY|action:\s*DENY",
        "allow": r"ALLOW|action:\s*ALLOW",
    },
    "Gateway": {
        "kind": r"kind:\s*Gateway",
        "servers": r"servers:",
        "tls_mode": r"tls:",
    },
}

# Linkerd CRD patterns
LINKERD_CRDS = {
    "ServiceProfile": {
        "kind": r"kind:\s*ServiceProfile",
        "routes": r"routes:",
    },
    "Server": {
        "kind": r"kind:\s*Server",
        "pod_selector": r"podSelector:",
        "proxy_protocol": r"proxyProtocol:",
    },
    "ServerAuthorization": {
        "kind": r"kind:\s*ServerAuthorization",
        "client": r"client:",
        "server": r"server:",
    },
    "TrafficSplit": {
        "kind": r"kind:\s*TrafficSplit",
        "backends": r"backends:",
        "weighted": r"weighted:",
    },
}

# mTLS mode patterns
MTLS_PATTERNS = [
    (r"mode:\s*STRICT", "mTLS strict mode (good)", Severity.INFO),
    (r"mode:\s*PERMISSIVE", "mTLS permissive mode (weak)", Severity.MEDIUM),
    (r"mode:\s*DISABLE", "mTLS disabled", Severity.HIGH),
    (r"mtls:\s*\{\s*\}", "mTLS empty config (defaults may apply)", Severity.MEDIUM),
]

# Sidecar injection patterns
SIDECAR_PATTERNS = [
    (r"sidecar\.istio\.io/inject:\s*[\"']?true[\"']?", "Sidecar injection enabled"),
    (r"sidecar\.istio\.io/inject:\s*[\"']?false[\"']?", "Sidecar injection disabled"),
    (r"linkerd\.io/inject:\s*[\"']?enabled[\"']?", "Linkerd injection enabled"),
    (r"linkerd\.io/inject:\s*[\"']?disabled[\"']?", "Linkerd injection disabled"),
]

# Default deny patterns
DEFAULT_DENY_PATTERNS = [
    (r"action:\s*DENY.*\n.*rules:\s*\[\s*\]", "Default deny policy with empty rules"),
    (r"action:\s*DENY", "DENY action policy"),
    (r"action:\s*ALLOW", "ALLOW action policy"),
]

CONTROL_IDS = {
    "MESH-01": ("mTLS not in strict mode", Severity.HIGH),
    "MESH-02": ("Missing PeerAuthentication", Severity.MEDIUM),
    "MESH-03": ("Sidecar injection not configured", Severity.MEDIUM),
    "MESH-04": ("No AuthorizationPolicy (default allow)", Severity.MEDIUM),
    "MESH-05": ("Missing default-deny policy", Severity.MEDIUM),
    "MESH-06": ("VirtualService without TLS", Severity.MEDIUM),
    "MESH-07": ("Service mesh CRD detected", Severity.INFO),
}


_log = logging.getLogger("patchi.security.service_mesh_agent")


@register
class ServiceMeshAgent(BaseAgent):
    name = "ServiceMeshAgent"
    group = AgentGroup.SECURITY
    description = "Service mesh security: mTLS enforcement, sidecar injection, RBAC least privilege, authorization policies"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        with trace_agent(self.name, inp.root) as trace:
            findings: list[Finding] = []
            files_scanned = 0

            # Track which CRDs we find for aggregate analysis
            found_crds: dict[str, list[str]] = {}
            has_peer_auth = False
            has_authz_policy = False
            has_default_deny = False

            # Phase 1: Scan YAML/JSON for service mesh CRDs
            for fpath in safe_rglob(inp.root, "*.yaml"):
                files_scanned += 1
                self._scan_manifest(fpath, inp.root, findings, found_crds)
            for fpath in safe_rglob(inp.root, "*.yml"):
                files_scanned += 1
                self._scan_manifest(fpath, inp.root, findings, found_crds)

            # Phase 2: Scan Helm charts and values
            for fpath in safe_rglob(inp.root, "values.yaml"):
                files_scanned += 1
                self._scan_helm_values(fpath, inp.root, findings)

            # Phase 3: Scan Helm templates for CRD generation
            for fpath in safe_rglob(inp.root, "*.tpl"):
                files_scanned += 1
                self._scan_manifest(fpath, inp.root, findings, found_crds)

            # Phase 4: Aggregate analysis
            crd_types = set(found_crds.keys())
            has_peer_auth = "PeerAuthentication" in crd_types
            has_authz_policy = "AuthorizationPolicy" in crd_types

            # Check for missing PeerAuthentication
            if crd_types and not has_peer_auth:
                findings.append(
                    make_finding(
                        Severity.MEDIUM,
                        "",
                        0,
                        "MESH-02: No PeerAuthentication found",
                        "Service mesh CRDs detected but no PeerAuthentication policy. mTLS may not be enforced.",
                        suggestion="Add PeerAuthentication with mode=STRICT for all namespaces",
                        control_id="MESH-02",
                    )
                )

            # Check for missing AuthorizationPolicy
            if crd_types and not has_authz_policy:
                findings.append(
                    make_finding(
                        Severity.MEDIUM,
                        "",
                        0,
                        "MESH-04: No AuthorizationPolicy (default allow)",
                        "Service mesh CRDs detected but no AuthorizationPolicy. All traffic may be allowed by default.",
                        suggestion="Implement default-deny AuthorizationPolicy and explicit ALLOW rules",
                        control_id="MESH-04",
                    )
                )

            # Check for missing default-deny
            if crd_types and not has_default_deny:
                findings.append(
                    make_finding(
                        Severity.MEDIUM,
                        "",
                        0,
                        "MESH-05: No default-deny policy detected",
                        "No DENY action policy found. Consider implementing default-deny for least privilege.",
                        suggestion="Create default-deny AuthorizationPolicy in each namespace",
                        control_id="MESH-05",
                    )
                )

            # Phase 5: Try external tools
            # Try istioctl analyze
            istioctl_path = shutil.which("istioctl")
            if istioctl_path:
                try:
                    proc = subprocess.run(
                        [istioctl_path, "analyze", "--namespace", "default", str(inp.root)],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    output = proc.stdout + proc.stderr
                    if output and "Error" in output:
                        for line in output.split("\n"):
                            if "Error" in line or "Warning" in line:
                                severity = Severity.HIGH if "Error" in line else Severity.MEDIUM
                                findings.append(
                                    make_finding(
                                        severity,
                                        "",
                                        0,
                                        f"istioctl: {line.strip()[:80]}",
                                        line.strip(),
                                        suggestion="Fix istioctl analysis finding",
                                    )
                                )
                except (subprocess.TimeoutExpired, Exception):
                    pass

            # Try kube-linter
            kube_linter_path = shutil.which("kube-linter")
            if kube_linter_path:
                try:
                    proc = subprocess.run(
                        [kube_linter_path, "lint", str(inp.root), "--format", "json"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    if proc.stdout:
                        import json

                        try:
                            data = json.loads(proc.stdout)
                            for item in data.get("objects", []):
                                for diag in item.get("diagnostics", []):
                                    check = diag.get("check", "")
                                    if any(
                                        kw in check.lower()
                                        for kw in ["mtls", "auth", "mesh", "sidecar"]
                                    ):
                                        findings.append(
                                            make_finding(
                                                Severity.MEDIUM,
                                                item.get("metadata", {}).get("filePath", ""),
                                                0,
                                                f"kube-linter: {check}",
                                                diag.get("message", ""),
                                                suggestion="Review kube-linter finding for mesh security impact",
                                            )
                                        )
                        except json.JSONDecodeError:
                            pass
                except (subprocess.TimeoutExpired, Exception):
                    pass

            result.findings = findings
            result.files_scanned = files_scanned
            result.status = AgentStatus.DONE
            trace.findings = len(findings)
            trace.files_scanned = files_scanned

            return

    def _scan_manifest(self, fpath: Path, root: Path, findings: list, found_crds: dict) -> None:
        """Scan a YAML/YML file for service mesh CRDs."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            _log.warning("ServiceMeshAgent._scan_manifest failed: %s", e)
            return

        rel = str(fpath.relative_to(root))

        # Check for Istio CRDs
        for crd_name, patterns in ISTIO_CRDS.items():
            if re.search(patterns["kind"], content):
                found_crds.setdefault(crd_name, []).append(rel)
                findings.append(
                    make_finding(
                        Severity.INFO,
                        rel,
                        0,
                        f"MESH-07: Istio CRD detected: {crd_name}",
                        f"Found {crd_name} custom resource. Verify security configuration.",
                        control_id="MESH-07",
                    )
                )

                # Check mTLS configuration in PeerAuthentication
                if crd_name == "PeerAuthentication":
                    for pattern, desc, severity in MTLS_PATTERNS:
                        if re.search(pattern, content):
                            if severity != Severity.INFO:
                                findings.append(
                                    make_finding(
                                        severity,
                                        rel,
                                        0,
                                        f"MESH-01: {desc}",
                                        f"PeerAuthentication {desc}. All mesh traffic should use mTLS STRICT.",
                                        suggestion="Set mTLS mode to STRICT for all PeerAuthentication policies",
                                        control_id="MESH-01",
                                    )
                                )

                # Check for sidecar injection in Deployment/Service
                if crd_name in ("VirtualService", "DestinationRule"):
                    for pattern, desc in SIDECAR_PATTERNS:
                        if re.search(pattern, content):
                            if "disabled" in desc.lower() or "false" in desc.lower():
                                findings.append(
                                    make_finding(
                                        Severity.MEDIUM,
                                        rel,
                                        0,
                                        "MESH-03: Sidecar injection disabled",
                                        desc,
                                        suggestion="Enable sidecar injection for mesh security benefits",
                                        control_id="MESH-03",
                                    )
                                )

        # Check for Linkerd CRDs
        for crd_name, patterns in LINKERD_CRDS.items():
            if re.search(patterns["kind"], content):
                found_crds.setdefault(crd_name, []).append(rel)
                findings.append(
                    make_finding(
                        Severity.INFO,
                        rel,
                        0,
                        f"MESH-07: Linkerd CRD detected: {crd_name}",
                        f"Found {crd_name} custom resource. Verify security configuration.",
                        control_id="MESH-07",
                    )
                )

        # Check for default-deny patterns
        for pattern, desc in DEFAULT_DENY_PATTERNS:
            if re.search(pattern, content, re.DOTALL):
                if "DENY" in desc:
                    findings.append(
                        make_finding(
                            Severity.INFO,
                            rel,
                            0,
                            f"MESH-05: {desc}",
                            desc,
                            control_id="MESH-05",
                        )
                    )

    def _scan_helm_values(self, fpath: Path, root: Path, findings: list) -> None:
        """Scan Helm values files for mesh configuration."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            _log.warning("ServiceMeshAgent._scan_helm_values failed: %s", e)
            return

        rel = str(fpath.relative_to(root))

        # Check for Istio Helm values
        if re.search(r"istio|mesh|sidecar", content, re.IGNORECASE):
            # Check mTLS settings
            mtls_match = re.search(r"mtls:\s*\n\s*(?:enabled|mode):\s*(\w+)", content)
            if mtls_match:
                mode = mtls_match.group(1)
                if mode.lower() not in ("strict", "true"):
                    findings.append(
                        make_finding(
                            Severity.MEDIUM,
                            rel,
                            0,
                            "MESH-01: mTLS not in strict mode in Helm values",
                            f"Helm values specify mTLS mode={mode}. Use STRICT for production.",
                            suggestion="Set mtls.enabled=true or mtls.mode=STRICT",
                            control_id="MESH-01",
                        )
                    )

            # Check sidecar injection
            injection_match = re.search(
                r"sidecar.*inject(?:ion)?:\s*\n\s*enabled:\s*(\w+)", content
            )
            if injection_match and injection_match.group(1).lower() == "false":
                findings.append(
                    make_finding(
                        Severity.MEDIUM,
                        rel,
                        0,
                        "MESH-03: Sidecar injection disabled in Helm values",
                        "Helm values have sidecar injection disabled. Services won't get mesh security.",
                        suggestion="Enable sidecar injection in Helm values",
                        control_id="MESH-03",
                    )
                )
