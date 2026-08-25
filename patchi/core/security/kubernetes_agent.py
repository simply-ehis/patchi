"""Kubernetes cluster hardening agent — validates manifests against CIS Benchmarks."""

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

# Kubernetes manifest detection
K8S_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Service",
    "ConfigMap",
    "Secret",
    "ServiceAccount",
    "ClusterRole",
    "ClusterRoleBinding",
    "Role",
    "RoleBinding",
    "NetworkPolicy",
    "Ingress",
    "PersistentVolumeClaim",
    "PersistentVolume",
    "Namespace",
    "LimitRange",
    "ResourceQuota",
    "HorizontalPodAutoscaler",
    "Job",
    "CronJob",
    "CustomResourceDefinition",
    "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration",
    "PodDisruptionBudget",
}

# CIS Benchmark patterns
CIS_PATTERNS = {
    "anonymous_auth": {
        "pattern": r"anonymous-auth:\s*true|anonymous.*auth.*true",
        "control": "K8S-01",
        "title": "Anonymous authentication enabled",
        "severity": Severity.HIGH,
        "description": "Anonymous authentication is enabled on the API server. Disable it.",
        "suggestion": "Set --anonymous-auth=false on kube-apiserver",
    },
    "insecure_port": {
        "pattern": r"insecure-port:\s*[1-9]\d*|insecure.bind-address",
        "control": "K8S-02",
        "title": "Insecure port enabled",
        "severity": Severity.CRITICAL,
        "description": "Insecure port is configured. API server traffic may be unencrypted.",
        "suggestion": "Set --insecure-port=0 to disable insecure port",
    },
    "audit_log": {
        "pattern": r"audit-log-path|audit-policy|audit.log|audit-file",
        "control": "K8S-03",
        "title": "Audit logging configured",
        "severity": Severity.INFO,
        "description": "Audit logging configuration detected.",
    },
    "tls_cert": {
        "pattern": r"tls-cert-file|tls-private-key|cert-file|key-file",
        "control": "K8S-04",
        "title": "TLS configured",
        "severity": Severity.INFO,
        "description": "TLS certificate configuration detected.",
    },
    "etcd_encryption": {
        "pattern": r"encryption-provider-config|encryption-provider|etcd-encryption",
        "control": "K8S-05",
        "title": "etcd encryption configured",
        "severity": Severity.INFO,
        "description": "etcd encryption at rest configuration detected.",
    },
}

# Pod security patterns
POD_SECURITY_PATTERNS = {
    "privileged": {
        "pattern": r"privileged:\s*true",
        "control": "K8S-06",
        "title": "Privileged container",
        "severity": Severity.CRITICAL,
        "description": "Container runs in privileged mode with full host access.",
        "suggestion": "Remove privileged: true and use specific capabilities instead",
        "cwe": "CWE-250",
    },
    "host_path": {
        "pattern": r"hostPath:",
        "control": "K8S-07",
        "title": "hostPath volume mounted",
        "severity": Severity.HIGH,
        "description": "Container mounts host filesystem via hostPath. May expose sensitive host data.",
        "suggestion": "Use PersistentVolumeClaims or emptyDir instead of hostPath",
        "cwe": "CWE-284",
    },
    "host_network": {
        "pattern": r"hostNetwork:\s*true",
        "control": "K8S-08",
        "title": "Host network namespace",
        "severity": Severity.HIGH,
        "description": "Container uses host network namespace. May intercept host traffic.",
        "suggestion": "Remove hostNetwork: true unless strictly required",
        "cwe": "CWE-668",
    },
    "host_pid": {
        "pattern": r"hostPID:\s*true",
        "control": "K8S-09",
        "title": "Host PID namespace",
        "severity": Severity.HIGH,
        "description": "Container shares host PID namespace. Can see all host processes.",
        "suggestion": "Remove hostPID: true unless required for debugging",
        "cwe": "CWE-693",
    },
    "run_as_root": {
        "pattern": r"runAsNonRoot:\s*false|securityContext:\s*\n\s*runAsUser:\s*0",
        "control": "K8S-10",
        "title": "Container runs as root",
        "severity": Severity.HIGH,
        "description": "Container runs as root user. Compromise may lead to host root access.",
        "suggestion": "Set runAsNonRoot: true and runAsUser: non-zero",
        "cwe": "CWE-250",
    },
    "capabilities_add": {
        "pattern": r"add:\s*\n\s*-\s*ALL|capabilities:\s*\n\s*add:",
        "control": "K8S-11",
        "title": "Excessive Linux capabilities",
        "severity": Severity.HIGH,
        "description": "Container adds Linux capabilities. ALL capabilities is equivalent to privileged.",
        "suggestion": "Add only the minimum required capabilities and drop ALL by default",
        "cwe": "CWE-250",
    },
    "read_only_rootfs": {
        "pattern": r"readOnlyRootFilesystem:\s*false",
        "control": "K8S-12",
        "title": "Writable root filesystem",
        "severity": Severity.MEDIUM,
        "description": "Container root filesystem is writable. Malware may persist.",
        "suggestion": "Set readOnlyRootFilesystem: true and use volumes for writable paths",
    },
    "default_namespace": {
        "pattern": r"namespace:\s*default|metadata:\s*\n\s*name:\s*\w+",
        "control": "K8S-13",
        "title": "Default namespace usage",
        "severity": Severity.LOW,
        "description": "Resource uses the default namespace. Production workloads should use dedicated namespaces.",
        "suggestion": "Use a dedicated namespace for production workloads",
    },
}

# RBAC patterns
RBAC_PATTERNS = {
    "wildcard_verbs": {
        "pattern": r"verbs:\s*\n\s*-\s*\*|verbs:\s*\[\s*\"\*\"\s*\]",
        "control": "K8S-14",
        "title": "RBAC wildcard verbs",
        "severity": Severity.HIGH,
        "description": "RBAC rule grants wildcard verbs. Service account has excessive permissions.",
        "suggestion": "Specify only required verbs (get, list, watch, create, update, patch, delete)",
        "cwe": "CWE-269",
    },
    "wildcard_resources": {
        "pattern": r"resources:\s*\n\s*-\s*\*|resources:\s*\[\s*\"\*\"\s*\]",
        "control": "K8S-15",
        "title": "RBAC wildcard resources",
        "severity": Severity.HIGH,
        "description": "RBAC rule grants access to all resources. Principle of least privilege violated.",
        "suggestion": "Specify only the required resources",
        "cwe": "CWE-269",
    },
    "cluster_admin": {
        "pattern": r"cluster-admin|ClusterRoleBinding.*cluster-admin|roleRef:\s*\n\s*name:\s*cluster-admin",
        "control": "K8S-16",
        "title": "cluster-admin binding",
        "severity": Severity.HIGH,
        "description": "Binding to cluster-admin grants full cluster access.",
        "suggestion": "Create a custom Role/ClusterRole with only required permissions",
        "cwe": "CWE-269",
    },
    "service_account_token": {
        "pattern": r"automountServiceAccountToken:\s*true|automount.*token.*true",
        "control": "K8S-17",
        "title": "Service account token auto-mounted",
        "severity": Severity.MEDIUM,
        "description": "Service account token is automatically mounted. Pods may access API server.",
        "suggestion": "Set automountServiceAccountToken: false if API access is not needed",
        "cwe": "CWE-200",
    },
}

# Network policy patterns
NETWORK_POLICY_PATTERNS = {
    "no_network_policy": {
        "pattern": r"kind:\s*NetworkPolicy",
        "control": "K8S-18",
        "title": "NetworkPolicy found",
        "severity": Severity.INFO,
        "description": "NetworkPolicy resource detected.",
    },
    "ingress_allow_all": {
        "pattern": r"ingress:\s*\n\s*-\s*\{\s*\}|ingress:\s*\n\s*-\s*from:\s*\n\s*-\s*\{\s*\}",
        "control": "K8S-19",
        "title": "NetworkPolicy allows all ingress",
        "severity": Severity.MEDIUM,
        "description": "NetworkPolicy allows ingress from all sources. Network segmentation not enforced.",
        "suggestion": "Restrict ingress to specific pods/namespaces",
    },
}

CONTROL_IDS = {
    "K8S-01": ("Anonymous authentication enabled", Severity.HIGH),
    "K8S-02": ("Insecure port enabled", Severity.CRITICAL),
    "K8S-03": ("Audit logging", Severity.INFO),
    "K8S-04": ("TLS configured", Severity.INFO),
    "K8S-05": ("etcd encryption", Severity.INFO),
    "K8S-06": ("Privileged container", Severity.CRITICAL),
    "K8S-07": ("hostPath volume", Severity.HIGH),
    "K8S-08": ("Host network", Severity.HIGH),
    "K8S-09": ("Host PID", Severity.HIGH),
    "K8S-10": ("Container runs as root", Severity.HIGH),
    "K8S-11": ("Excessive capabilities", Severity.HIGH),
    "K8S-12": ("Writable root filesystem", Severity.MEDIUM),
    "K8S-13": ("Default namespace", Severity.LOW),
    "K8S-14": ("RBAC wildcard verbs", Severity.HIGH),
    "K8S-15": ("RBAC wildcard resources", Severity.HIGH),
    "K8S-16": ("cluster-admin binding", Severity.HIGH),
    "K8S-17": ("Service account token auto-mounted", Severity.MEDIUM),
    "K8S-18": ("NetworkPolicy found", Severity.INFO),
    "K8S-19": ("NetworkPolicy allows all ingress", Severity.MEDIUM),
    "K8S-20": ("Missing network policy", Severity.MEDIUM),
}


_log = logging.getLogger("patchi.security.kubernetes_agent")


@register
class KubernetesAgent(BaseAgent):
    name = "KubernetesAgent"
    group = AgentGroup.SECURITY
    description = (
        "Kubernetes cluster hardening: CIS Benchmark controls, RBAC, pod security, network policies"
    )

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        with trace_agent(self.name, inp.root) as trace:
            findings: list[Finding] = []
            files_scanned = 0
            k8s_manifests = 0
            namespaces_seen: set[str] = set()
            has_network_policy = False

            # Phase 1: Scan YAML files for Kubernetes manifests
            for fpath in safe_rglob(inp.root, "*.yaml"):
                files_scanned += 1
                self._scan_yaml(fpath, inp.root, findings, namespaces_seen, "has_network_policy")
            for fpath in safe_rglob(inp.root, "*.yml"):
                files_scanned += 1
                self._scan_yaml(fpath, inp.root, findings, namespaces_seen, "has_network_policy")

            # Check if any NetworkPolicy was found
            has_network_policy = any(f.message.startswith("K8S-18:") for f in findings)

            # Phase 2: Scan Helm charts
            for fpath in safe_rglob(inp.root, "Chart.yaml"):
                files_scanned += 1
                self._scan_helm_chart(fpath, inp.root, findings)

            # Phase 3: Scan Dockerfiles for security issues
            for fpath in safe_rglob(inp.root, "Dockerfile*"):
                files_scanned += 1
                self._scan_dockerfile(fpath, inp.root, findings)

            # Phase 4: Aggregate analysis
            # Check for missing network policies
            if namespaces_seen and not has_network_policy:
                findings.append(
                    make_finding(
                        Severity.MEDIUM,
                        "",
                        0,
                        "K8S-20: No NetworkPolicy found",
                        f"Found {len(namespaces_seen)} namespace(s) but no NetworkPolicy. Network segmentation not enforced.",
                        suggestion="Add NetworkPolicy to restrict pod-to-pod communication",
                        control_id="K8S-20",
                    )
                )

            # Phase 5: Try external tools
            # Try kube-bench (CIS Benchmark scanner)
            kube_bench_path = shutil.which("kube-bench")
            if kube_bench_path:
                try:
                    proc = subprocess.run(
                        [kube_bench_path, "run", "--json", "--targets", "master,node,policies"],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if proc.stdout:
                        import json

                        try:
                            data = json.loads(proc.stdout)
                            for check in data.get("tests", []):
                                for result_item in check.get("results", []):
                                    if result_item.get("status") == "FAIL":
                                        findings.append(
                                            make_finding(
                                                Severity.HIGH,
                                                "",
                                                0,
                                                f"kube-bench: {result_item.get('test_desc', 'Unknown')}",
                                                f"CIS Benchmark check failed: {result_item.get('test_desc', '')}",
                                                suggestion="Fix kube-bench finding per CIS Kubernetes Benchmark",
                                            )
                                        )
                        except json.JSONDecodeError:
                            pass
                except (subprocess.TimeoutExpired, Exception):
                    pass

            # Try kubectl for cluster state
            kubectl_path = shutil.which("kubectl")
            if kubectl_path:
                try:
                    # Check for RBAC
                    proc = subprocess.run(
                        [kubectl_path, "get", "clusterrolebindings", "-o", "json"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        import json

                        try:
                            data = json.loads(proc.stdout)
                            for item in data.get("items", []):
                                role_ref = item.get("roleRef", {})
                                if role_ref.get("name") == "cluster-admin":
                                    subjects = item.get("subjects", [])
                                    for subject in subjects:
                                        findings.append(
                                            make_finding(
                                                Severity.HIGH,
                                                "",
                                                0,
                                                "K8S-16: cluster-admin binding via kubectl",
                                                f"cluster-admin bound to: {subject.get('name', 'unknown')} ({subject.get('kind', 'unknown')})",
                                                suggestion="Review and remove unnecessary cluster-admin bindings",
                                                cwe="CWE-269",
                                                control_id="K8S-16",
                                            )
                                        )
                        except json.JSONDecodeError:
                            pass
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
                                        for kw in [
                                            "privileged",
                                            "hostpath",
                                            "network",
                                            "rbac",
                                            "capability",
                                        ]
                                    ):
                                        findings.append(
                                            make_finding(
                                                Severity.MEDIUM,
                                                item.get("metadata", {}).get("filePath", ""),
                                                0,
                                                f"kube-linter: {check}",
                                                diag.get("message", ""),
                                                suggestion="Review kube-linter finding for Kubernetes security impact",
                                            )
                                        )
                        except json.JSONDecodeError:
                            pass
                except (subprocess.TimeoutExpired, Exception):
                    pass

            result.findings = findings
            result.files_scanned = files_scanned
            result.data = {
                "k8s_manifests": k8s_manifests,
                "namespaces_seen": list(namespaces_seen),
                "has_network_policy": has_network_policy,
            }
            result.status = AgentStatus.DONE
            trace.findings = len(findings)
            trace.files_scanned = files_scanned

            return

    def _scan_yaml(
        self,
        fpath: Path,
        root: Path,
        findings: list,
        namespaces_seen: set,
        network_policy_flag: str,
    ) -> None:
        """Scan a YAML/YML file for Kubernetes manifests."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            _log.warning("KubernetesAgent._scan_yaml failed: %s", e)
            return

        # Quick check: is this a Kubernetes manifest?
        if not re.search(r"apiVersion:\s*", content):
            return

        rel = str(fpath.relative_to(root))
        kind_match = re.search(r"kind:\s*(\w+)", content)
        if not kind_match:
            return

        kind = kind_match.group(1)
        if kind not in K8S_KINDS:
            return

        # Extract namespace if present
        ns_match = re.search(r"namespace:\s*(\S+)", content)
        if ns_match:
            namespaces_seen.add(ns_match.group(1))

        # CIS Benchmark checks for kube-apiserver/kubelet configs
        for _check_id, check_info in CIS_PATTERNS.items():
            if re.search(check_info["pattern"], content, re.IGNORECASE):
                findings.append(
                    make_finding(
                        check_info["severity"],
                        rel,
                        0,
                        f"{check_info['control']}: {check_info['title']}",
                        check_info["description"],
                        suggestion=check_info.get("suggestion", ""),
                        control_id=check_info["control"],
                    )
                )

        # Pod security checks
        for _check_id, check_info in POD_SECURITY_PATTERNS.items():
            if re.search(check_info["pattern"], content, re.IGNORECASE):
                findings.append(
                    make_finding(
                        check_info["severity"],
                        rel,
                        0,
                        f"{check_info['control']}: {check_info['title']}",
                        check_info["description"],
                        suggestion=check_info.get("suggestion", ""),
                        cwe=check_info.get("cwe", ""),
                        control_id=check_info["control"],
                    )
                )

        # RBAC checks
        for _check_id, check_info in RBAC_PATTERNS.items():
            if re.search(check_info["pattern"], content, re.IGNORECASE):
                findings.append(
                    make_finding(
                        check_info["severity"],
                        rel,
                        0,
                        f"{check_info['control']}: {check_info['title']}",
                        check_info["description"],
                        suggestion=check_info.get("suggestion", ""),
                        cwe=check_info.get("cwe", ""),
                        control_id=check_info["control"],
                    )
                )

        # Network policy checks
        for _check_id, check_info in NETWORK_POLICY_PATTERNS.items():
            if re.search(check_info["pattern"], content, re.IGNORECASE):
                findings.append(
                    make_finding(
                        check_info["severity"],
                        rel,
                        0,
                        f"{check_info['control']}: {check_info['title']}",
                        check_info["description"],
                        suggestion=check_info.get("suggestion", ""),
                        control_id=check_info["control"],
                    )
                )

        # Check for missing securityContext
        if kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            if "securityContext" not in content and kind in ("Pod",):
                findings.append(
                    make_finding(
                        Severity.MEDIUM,
                        rel,
                        0,
                        "K8S-06: No securityContext defined",
                        "Pod does not define securityContext. Default settings may be permissive.",
                        suggestion="Add securityContext with runAsNonRoot, readOnlyRootFilesystem, and drop ALL capabilities",
                        control_id="K8S-06",
                    )
                )

        # Check for missing resource limits
        if kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            if "resources:" not in content:
                findings.append(
                    make_finding(
                        Severity.LOW,
                        rel,
                        0,
                        "K8S-12: No resource limits defined",
                        "Container does not define resource limits. May consume unlimited cluster resources.",
                        suggestion="Add resource limits (cpu, memory) to prevent resource exhaustion",
                    )
                )

    def _scan_helm_chart(self, fpath: Path, root: Path, findings: list) -> None:
        """Scan Helm chart metadata."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            _log.warning("KubernetesAgent._scan_helm_chart failed: %s", e)
            return

        rel = str(fpath.relative_to(root))

        # Check for deprecated API versions
        api_version = re.search(r"apiVersion:\s*(\S+)", content)
        if api_version and api_version.group(1) == "v1":
            findings.append(
                make_finding(
                    Severity.LOW,
                    rel,
                    0,
                    "K8S-13: Deprecated Helm chart API version",
                    "Helm chart uses apiVersion: v1 (deprecated). Upgrade to v2.",
                    suggestion="Migrate to Helm v3 (apiVersion: v2)",
                )
            )

    def _scan_dockerfile(self, fpath: Path, root: Path, findings: list) -> None:
        """Scan Dockerfile for Kubernetes-relevant security issues."""
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            _log.warning("KubernetesAgent._scan_dockerfile failed: %s", e)
            return

        rel = str(fpath.relative_to(root))

        # Check for running as root
        if not re.search(r"USER\s+\w+", content):
            findings.append(
                make_finding(
                    Severity.HIGH,
                    rel,
                    0,
                    "K8S-10: Dockerfile runs as root",
                    "Dockerfile does not set a non-root USER. Container will run as root.",
                    suggestion="Add 'USER nonroot' before the ENTRYPOINT/CMD",
                    cwe="CWE-250",
                    control_id="K8S-10",
                )
            )

        # Check for ADD instead of COPY
        if re.search(r"^ADD\s+", content, re.MULTILINE):
            findings.append(
                make_finding(
                    Severity.LOW,
                    rel,
                    0,
                    "K8S-12: Dockerfile uses ADD instead of COPY",
                    "ADD instruction may unpack archives or fetch URLs. COPY is more predictable.",
                    suggestion="Use COPY unless ADD functionality is specifically needed",
                )
            )

        # Check for apt-get without cleanup
        if re.search(r"apt-get\s+install", content) and not re.search(
            r"apt-get\s+clean|rm\s+-rf\s+/var/lib/apt", content
        ):
            findings.append(
                make_finding(
                    Severity.LOW,
                    rel,
                    0,
                    "K8S-12: apt-get install without cleanup",
                    "Package manager cache not cleaned. Increases image size and may contain vulnerabilities.",
                    suggestion="Add 'RUN apt-get clean && rm -rf /var/lib/apt/lists/*' after install",
                )
            )
