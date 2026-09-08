"""Falco Runtime Agent — container escape & runtime threat detection.

Detects:
- Missing Falco integration in container deployments
- Weak Falco rules that miss container escape patterns
- Runtime security misconfigurations (privileged containers, host PID/IPC, SYS_ADMIN)
- Container escape indicators in test/audit data
- Missing seccomp/AppArmor profiles
- Missing readOnlyRootFilesystem

Integration points:
1. Static analysis of IaC (Dockerfile, docker-compose, K8s manifests, Falco rules)
2. Detection of `/proc`, `cgroup`, `nsenter`, `mount` escape techniques in code
"""

from __future__ import annotations

import logging
import re

from ..agents.base import (
    AgentDomain,
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.security.falco_runtime_agent")


@register
class FalcoRuntimeAgent(BaseAgent):
    """Detect container escape risks and missing Falco runtime protection."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "FalcoRuntimeAgent"
    description = "Container escape detection & Falco runtime protection audit"

    # ── Container escape patterns (positive match = issue) ──
    ESCAPE_IAC_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "privileged_container",
            r"privileged:\s*true",
            "Privileged container — allows host namespace access",
            Severity.CRITICAL,
        ),
        (
            "host_pid",
            r"pid:\s*\"?host\"?",
            "Host PID namespace — container can see host processes",
            Severity.HIGH,
        ),
        (
            "host_network",
            r"network_mode:\s*\"?host\"?",
            "Host network — container bypasses network isolation",
            Severity.HIGH,
        ),
        (
            "host_ipc",
            r"ipc:\s*\"?host\"?",
            "Host IPC namespace — shared memory with host",
            Severity.HIGH,
        ),
        (
            "sys_admin_cap",
            r"CAP_SYS_ADMIN(?:_TRUSTED)?",
            "SYS_ADMIN capability — allows mount, namespace operations",
            Severity.CRITICAL,
        ),
        (
            "no_seccomp",
            r"security_opt:\s*\[\s*\"?unconfined\"?\]",
            "Seccomp unconfined — no syscall filtering",
            Severity.HIGH,
        ),
        (
            "no_apparmor",
            r"security_opt:\s*\[\s*\"?apparmor=unconfined\"?\]",
            "AppArmor unconfined — no mandatory access control",
            Severity.HIGH,
        ),
        (
            "root_user_container",
            r"USER\s+root",
            "Container runs as root — privilege escalation risk",
            Severity.MEDIUM,
        ),
        (
            "writable_rootfs",
            r"readOnlyRootFilesystem:\s*false",
            "Read-write root filesystem — tampering risk",
            Severity.MEDIUM,
        ),
        (
            "docker_sock_mount",
            r"/var/run/docker\.sock",
            "Docker socket mounted — container escape via Docker API",
            Severity.CRITICAL,
        ),
        (
            "host_path_mount",
            r"/:/rootfs|/:/host|/proc:/host/proc",
            "Host filesystem mounted writable",
            Severity.CRITICAL,
        ),
        (
            "cgroup_escape",
            r"/sys/fs/cgroup.*rw",
            "Cgroup mounted writable — escape via cgroup_notify_on_release",
            Severity.CRITICAL,
        ),
    ]

    # ── Missing Falco rules (NOT found = issue) ──
    MISSING_FALCO_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "no_falco_daemonset",
            r"DaemonSet.*falco|falco.*DaemonSet",
            "Falco not deployed as DaemonSet in K8s cluster",
            Severity.HIGH,
        ),
        (
            "no_falco_rules_ref",
            r"rules:\s*-",
            "No Falco rules file referenced in deployment config",
            Severity.HIGH,
        ),
    ]

    # ── Escape technique patterns in source code ──
    ESCAPE_CODE_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "nsenter",
            r"nsenter\s+--target\s+\d+\s+--mount.*--uts.*--ipc.*--pid.*--",
            "nsenter used for namespace escape",
            Severity.CRITICAL,
        ),
        (
            "proc_mount",
            r"mount\s+-t\s+proc|mount.*/proc/",
            "Mount proc filesystem — potential pivot_root escape",
            Severity.HIGH,
        ),
        (
            "cgroup_escape_code",
            r"notify_on_release|cgroup\.procs.*\d|release_agent.*/bin",
            "Cgroup release_agent — container escape technique",
            Severity.CRITICAL,
        ),
        (
            "chroot_escape",
            r"chroot\s+[^/]",
            "chroot to non-standard path — potential breakout",
            Severity.HIGH,
        ),
        (
            "pivot_root",
            r"pivot_root\s+\.\s+\.",
            "pivot_root used — container filesystem escape",
            Severity.CRITICAL,
        ),
        (
            "copy_from_host",
            r"cp\s+/bin/sh\s+/tmp|copy.*busybox.*/tmp",
            "Copy host binary — lateral movement indicator",
            Severity.HIGH,
        ),
        (
            "kmod_escape",
            r"insmod|modprobe.*escape",
            "Kernel module load — container escape via kernel",
            Severity.CRITICAL,
        ),
        (
            "sched_setaffinity",
            r"sched_setaffinity[^)]*\d+",
            "Sched_setaffinity to foreign PID — cross-container",
            Severity.MEDIUM,
        ),
        (
            "ptrace_cross",
            r"ptrace\s*\(\s*PTRACE_ATTACH",
            "Ptrace to another container — process injection risk",
            Severity.HIGH,
        ),
    ]

    # ── Required Falco rules that should be present ──
    REQUIRED_FALCO_RULES: list[tuple[str, str]] = [
        ("container_shell", r"container.*shell|Spawn.*shell"),
        ("privileged_container", r"privileged.*container|sensitive.*mount"),
        ("syscall_anomaly", r"syscall.*anomaly|unexpected.*syscall"),
        ("file_drop", r"drop.*binary|write.*binary|exec.*binary"),
        ("net_conn_suspicious", r"outbound.*connection|suspicious.*egress"),
        ("k8s_api_access", r"k8s.*api.*from.*container|kubernetes.*api.*call"),
    ]

    K8S_DIR_KEYWORDS = frozenset(
        {
            "kubernetes",
            "k8s",
            "deployment",
            "statefulset",
            "daemonset",
            "pod",
            "service",
            "ingress",
            "role",
            "configmap",
        }
    )

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        findings: list[Finding] = []

        # Find relevant files — single pass to avoid duplicates
        # safe_rglob yields generators — materialize before combining.
        dockerfiles = set(safe_rglob(root, "Dockerfile*"))
        compose_files = set(safe_rglob(root, "docker-compose*"))
        all_yaml = set(safe_rglob(root, "*.yaml")) | set(safe_rglob(root, "*.yml"))
        all_tf = set(safe_rglob(root, "*.tf"))
        code_files = (
            set(safe_rglob(root, "*.py"))
            | set(safe_rglob(root, "*.sh"))
            | set(safe_rglob(root, "*.go"))
            | set(safe_rglob(root, "*.rs"))
        )
        falco_files = [f for f in all_yaml if "falco" in str(f).lower()]

        # Phase 1: Scan IaC for escape misconfigs — unified set (no double-scanning)
        ia_files = dockerfiles | compose_files | all_yaml | all_tf
        seen_sc = False
        seen_nonroot = False
        seen_seccomp = False

        for fp in sorted(ia_files, key=str):
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                _log.warning("FalcoRuntimeAgent._run failed: %s", e)
                continue
            rel = str(fp.relative_to(root))
            fname = fp.name

            is_k8s = any(kw in str(fp).lower() for kw in self.K8S_DIR_KEYWORDS)
            is_dockerfile = "dockerfile" in fname.lower()
            is_compose = fname.lower().startswith("docker-compose")

            # Apply escape patterns based on file type
            for pname, pattern, msg, severity in self.ESCAPE_IAC_PATTERNS:
                if not (is_dockerfile or is_compose or is_k8s):
                    continue
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="iac_" + pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            cwe="CWE-250",
                        )
                    )

            # K8s-specific pod security context checks (once per project, not per file)
            if is_k8s and not seen_sc and "securityContext" not in text:
                seen_sc = True
                findings.append(
                    Finding(
                        agent=self.name,
                        type="no_security_context",
                        severity=Severity.HIGH,
                        file=rel,
                        message="K8s pod/container missing securityContext — enforce seccomp/AppArmor/runAsNonRoot",
                        cwe="CWE-250",
                    )
                )

            if is_k8s and not seen_nonroot and "runAsNonRoot: true" not in text:
                seen_nonroot = True
                findings.append(
                    Finding(
                        agent=self.name,
                        type="no_run_as_nonroot",
                        severity=Severity.MEDIUM,
                        file=rel,
                        message="K8s pod missing runAsNonRoot: true",
                        cwe="CWE-250",
                    )
                )

            if is_k8s and not seen_seccomp and "seccompProfile" not in text:
                seen_seccomp = True
                findings.append(
                    Finding(
                        agent=self.name,
                        type="no_seccomp_profile",
                        severity=Severity.MEDIUM,
                        file=rel,
                        message="K8s pod missing seccompProfile",
                        cwe="CWE-250",
                    )
                )

            # Falco deployment checks
            if is_k8s:
                for pname, pattern, msg, severity in self.MISSING_FALCO_PATTERNS:
                    if not re.search(pattern, text, re.IGNORECASE):
                        findings.append(
                            Finding(
                                agent=self.name,
                                type=pname,
                                severity=severity,
                                file=rel,
                                message=msg,
                                cwe="CWE-1104",
                            )
                        )

        # Phase 2: Check Falco rules presence and quality
        if not falco_files:
            findings.append(
                Finding(
                    agent=self.name,
                    type="no_falco_rules",
                    severity=Severity.HIGH,
                    file="",
                    message="No Falco rules files found — add runtime security monitoring",
                    cwe="CWE-1104",
                )
            )
        else:
            for fp in falco_files:
                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    _log.warning("FalcoRuntimeAgent._run failed: %s", e)
                    continue
                rel = str(fp.relative_to(root))
                for name, pattern in self.REQUIRED_FALCO_RULES:
                    if not re.search(pattern, text, re.IGNORECASE):
                        findings.append(
                            Finding(
                                agent=self.name,
                                type="missing_rule_" + name,
                                severity=Severity.MEDIUM,
                                file=rel,
                                message=f"Missing required Falco rule: {name}",
                                cwe="CWE-1104",
                            )
                        )

        # Phase 3: Escape technique patterns in source code
        for fp in sorted(code_files, key=str):
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                _log.warning("FalcoRuntimeAgent._run failed: %s", e)
                continue
            rel = str(fp.relative_to(root))
            for pname, pattern, msg, severity in self.ESCAPE_CODE_PATTERNS:
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="code_" + pname,
                            severity=severity,
                            file=rel,
                            message=msg,
                            line=1 + text[: m.start()].count("\n"),
                            snippet=m.group()[:80],
                            cwe="CWE-270",
                        )
                    )

        result.findings = findings
        result.status = AgentStatus.DONE
        result.files_scanned = len(ia_files) + len(falco_files) + len(code_files)
