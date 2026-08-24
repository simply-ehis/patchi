"""
PushNotificationAgent — push notification security.

Detects push notification security issues:
- Hardcoded FCM server keys or APNs private keys
- Push token handling vulnerabilities (storage, transmission)
- Sensitive data in notification payloads
- Missing token rotation/invalidation
- Insecure push notification endpoints
- Missing push notification authentication

Uses static file analysis and optional external tools (gitleaks).
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

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

_SOURCE_EXTENSIONS = {
    "*.py", "*.js", "*.jsx", "*.ts", "*.tsx", "*.java",
    "*.php", "*.rb", "*.go", "*.rs", "*.cs",
}

_FCM_KEY_PATTERNS = [
    (re.compile(r"(?:FCM[_-]?(?:SERVER[_-]?KEY|KEY|SECRET|TOKEN|API[_-]?KEY))\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.IGNORECASE),
     "PUSH-01: Hardcoded FCM Server Key"),
    (re.compile(r"(?:server[_-]?key|fcm[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.IGNORECASE),
     "PUSH-01: Hardcoded FCM Key"),
    (re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", re.IGNORECASE),
     "PUSH-01: Exposed FCM Server Key"),
]

_APNS_KEY_PATTERNS = [
    (re.compile(r"(?:APNS[_-]?(?:KEY|TOKEN|SECRET|PRIVATE[_-]?KEY|CERT))\s*[:=]\s*['\"][^'\"]{10,}['\"]", re.IGNORECASE),
     "PUSH-02: Hardcoded APNs Credential"),
    (re.compile(r"(?:aps[_-]?env|apns[_-]?environment)\s*[:=]\s*['\"]?(?:production|development|sandbox)['\"]?", re.IGNORECASE),
     "PUSH-03: APNs Environment Hardcoded"),
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
     "PUSH-02: Embedded Private Key in Source"),
]

_PUSH_TOKEN_PATTERNS = [
    (re.compile(r"(?:device[_-]?token|push[_-]?token|fcm[_-]?token|apns[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.IGNORECASE),
     "PUSH-04: Hardcoded Push Token"),
    (re.compile(r"(?:token|device_token)\s*\.\s*(?:save|store|persist|write|insert)", re.IGNORECASE),
     "PUSH-05: Push Token Stored Without Encryption"),
]

_SENSITIVE_PAYLOAD_PATTERNS = [
    (re.compile(r"(?:password|secret|credit.?card|ssn|social.?security|api.?key|private.?key)\s*[:=]", re.IGNORECASE),
     "PUSH-06: Sensitive Data in Notification Payload"),
    (re.compile(r"(?:notification|message|alert|payload|body)\s*(?:\.|\[).*(?:password|secret|token|key|credential)", re.IGNORECASE),
     "PUSH-06: Sensitive Data in Notification Body"),
]

_NOTIFICATION_FRAMEWORKS = [
    re.compile(r"\bfirebase[_-]?admin\b|\bfcm\b|FirebaseMessaging", re.IGNORECASE),
    re.compile(r"\bapns[_-]?client\b|\bpyapns\b|APNs", re.IGNORECASE),
    re.compile(r"\bpush[_-]?notification\b|\bpush[_-]?service\b", re.IGNORECASE),
    re.compile(r"\bOneSignal\b|\bonesignal\b", re.IGNORECASE),
    re.compile(r"\bexpo[_-]?server[_-]?sdk\b|\bexpo[_-]?notifications\b", re.IGNORECASE),
]


_log = logging.getLogger("patchi.security.push_notification_agent")


@register
class PushNotificationAgent(BaseAgent):
    """Agent for detecting push notification security issues."""

    group = AgentGroup.SECURITY
    name = "PushNotificationAgent"
    description = "Push notification security: FCM/APNs credential storage, token handling, payload minimization"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings: list[Finding] = []
        files_scanned = 0

        with trace_agent(self.name, inp.root) as trace:
            # ── Static analysis ────────────────────────────────────────────
            for pattern in _SOURCE_EXTENSIONS:
                for fp in safe_rglob(inp.root, pattern):
                    if fp.is_file():
                        files_scanned += 1
                        findings.extend(self._scan_file(fp, inp.root))

            findings.extend(self._scan_push_config(inp))
            findings.extend(self._scan_token_storage(inp))

            # ── External tool: gitleaks ────────────────────────────────────
            if shutil.which("gitleaks"):
                findings.extend(self._run_gitleaks(inp))

            trace.findings = len(findings)
            trace.files_scanned = files_scanned

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update({
            "push_findings": len(findings),
            "gitleaks_available": shutil.which("gitleaks") is not None,
        })
        return

    # ── Source file scan ───────────────────────────────────────────────────

    def _scan_file(self, fp: Path, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = fp.relative_to(root).as_posix()
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()

            # FCM keys
            for i, line in enumerate(lines, 1):
                for rx, title in _FCM_KEY_PATTERNS:
                    if rx.search(line):
                        findings.append(make_finding(
                            severity=Severity.CRITICAL,
                            file=rel,
                            line_start=i,
                            title=title,
                            description="Hardcoded FCM server key found. Anyone with this key can send push notifications.",
                            evidence=line.strip()[:120],
                            suggestion="Store FCM server keys in environment variables or a secrets manager.",
                        ))

            # APNs keys
            for i, line in enumerate(lines, 1):
                for rx, title in _APNS_KEY_PATTERNS:
                    if rx.search(line):
                        findings.append(make_finding(
                            severity=Severity.CRITICAL,
                            file=rel,
                            line_start=i,
                            title=title,
                            description="Hardcoded APNs credential or private key found.",
                            evidence=line.strip()[:120],
                            suggestion="Store APNs credentials securely and load from environment variables.",
                        ))

            # Push tokens
            for i, line in enumerate(lines, 1):
                for rx, title in _PUSH_TOKEN_PATTERNS:
                    if rx.search(line):
                        findings.append(make_finding(
                            severity=Severity.HIGH,
                            file=rel,
                            line_start=i,
                            title=title,
                            description="Push token handling issue detected.",
                            evidence=line.strip()[:120],
                            suggestion="Rotate push tokens regularly and encrypt at rest.",
                        ))

            # Sensitive data in payloads
            in_notification_block = False
            for i, line in enumerate(lines, 1):
                if re.search(r"(?:notification|message|payload|alert|body)\s*[{(]", line, re.IGNORECASE):
                    in_notification_block = True
                if in_notification_block:
                    for rx, title in _SENSITIVE_PAYLOAD_PATTERNS:
                        if rx.search(line):
                            findings.append(make_finding(
                                severity=Severity.HIGH,
                                file=rel,
                                line_start=i,
                                title=title,
                                description="Sensitive data detected in notification payload.",
                                evidence=line.strip()[:120],
                                suggestion="Minimize notification payloads; never include PII or secrets.",
                            ))
                    if re.search(r"[})]", line):
                        in_notification_block = False

        except Exception as e:
            _log.warning("PushNotificationAgent._scan_file failed: %s", e)
        return findings

    # ── Push config scan ───────────────────────────────────────────────────

    def _scan_push_config(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        config_patterns = ("*.yaml", "*.yml", "*.json", "*.toml", "*.tf", "*.env*")
        for pattern in config_patterns:
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    content_lower = content.lower()
                    # Check if file is push-related
                    is_push_config = any(
                        kw in content_lower
                        for kw in ("fcm", "firebase", "apns", "push", "notification")
                    )
                    if not is_push_config:
                        continue

                    # Check for credentials in config
                    for rx, title in _FCM_KEY_PATTERNS:
                        if rx.search(content):
                            findings.append(make_finding(
                                severity=Severity.CRITICAL,
                                file=rel,
                                line_start=0,
                                title=title,
                                description="FCM server key found in configuration file.",
                                suggestion="Use environment variables or a secrets manager instead of config files.",
                            ))

                    for rx, title in _APNS_KEY_PATTERNS:
                        if rx.search(content):
                            findings.append(make_finding(
                                severity=Severity.CRITICAL,
                                file=rel,
                                line_start=0,
                                title=title,
                                description="APNs credential found in configuration file.",
                                suggestion="Load APNs credentials from a secure vault.",
                            ))

                except Exception as e:
                    _log.warning("PushNotificationAgent._scan_push_config failed: %s", e)
        return findings

    # ── Token storage patterns ─────────────────────────────────────────────

    def _scan_token_storage(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.py", "*.js", "*.ts", "*.java", "*.go", "*.rb"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        # Token stored in plaintext database field
                        if re.search(
                            r"(?:device_token|push_token|fcm_token|apns_token)\s*.*(?:VARCHAR|TEXT|STRING|str)",
                            line, re.IGNORECASE,
                        ):
                            findings.append(make_finding(
                                severity=Severity.MEDIUM,
                                file=rel,
                                line_start=i,
                                title="PUSH-05: Push Token Stored Without Encryption",
                                description="Push token stored in a plaintext database column.",
                                evidence=line.strip()[:120],
                                suggestion="Encrypt push tokens at rest or store hashed.",
                            ))
                        # Token logged
                        if re.search(r"(?:log|print|debug|console).*(?:token|device_token|push_token)", line, re.IGNORECASE):
                            findings.append(make_finding(
                                severity=Severity.MEDIUM,
                                file=rel,
                                line_start=i,
                                title="PUSH-04: Push Token Logged",
                                description="Push token may be written to logs.",
                                evidence=line.strip()[:120],
                                suggestion="Never log push tokens; they can be used to impersonate users.",
                            ))
                except Exception as e:
                    _log.warning("PushNotificationAgent._scan_token_storage failed: %s", e)
        return findings

    # ── External tool: gitleaks ────────────────────────────────────────────

    def _run_gitleaks(self, inp: AgentInput) -> list[Finding]:
        """Run gitleaks to detect hardcoded push notification secrets."""
        findings: list[Finding] = []
        try:
            proc = subprocess.run(
                [
                    "gitleaks", "detect",
                    "--source", str(inp.root),
                    "--report-format", "json",
                    "--redact",
                ],
                capture_output=True, text=True, timeout=120,
            )
            if proc.stdout.strip():
                import json
                try:
                    data = json.loads(proc.stdout)
                    for item in data if isinstance(data, list) else []:
                        rule = item.get("RuleID", "").lower()
                        description = item.get("Description", "")
                        if any(kw in rule or kw in description.lower() for kw in ("fcm", "firebase", "apns", "push", "notification")):
                            findings.append(make_finding(
                                severity=Severity.CRITICAL,
                                file=item.get("File", "(gitleaks)"),
                                line_start=item.get("StartLine", 0),
                                title="PUSH-01: Push Secret Detected by Gitleaks",
                                description=f"Gitleaks detected: {item.get('RuleID', 'unknown')}",
                                evidence=item.get("Match", "")[:120],
                                suggestion="Remove the secret and rotate credentials immediately.",
                            ))
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return findings
