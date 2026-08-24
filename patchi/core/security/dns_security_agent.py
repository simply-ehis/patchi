"""
DNSSecurityAgent — DNS security issues.

Detects DNS-related security issues:
- Dangling/orphaned DNS records (subdomain takeover risk)
- Missing zone transfer protection
- Missing DNSSEC configuration
- Missing CAA records
- Terraform Route53 misconfigurations
- Exposed DNS zone files

Uses static file analysis and optional external tools (dig, nslookup, dnsReaper).
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

_DNS_CONFIG_NAMES = {
    "dns.tf", "route53.tf", "dns.yaml", "dns.yml", "dns.json",
    "named.conf", "zone.db", "db.", "db.",
    "corefile", "Corefile", "unbound.conf",
}

_ROUTE53_PATTERNS = [
    (re.compile(r"aws_route53_record", re.IGNORECASE), "Terraform Route53 record"),
    (re.compile(r"aws_route53_zone", re.IGNORECASE), "Terraform Route53 zone"),
    (re.compile(r"Route53|route53", re.IGNORECASE), "Route53 reference"),
]

_ZONE_TRANSFER_PATTERNS = [
    (re.compile(r"allow-transfer\s*\{[^}]*any", re.IGNORECASE),
     "DNS zone transfer allowed to any"),
    (re.compile(r"allow-transfer\s*\{[^}]*\}", re.IGNORECASE),
     "DNS zone transfer configured"),
    (re.compile(r"also-notify", re.IGNORECASE),
     "DNS secondary notification configured"),
]

_DNSSEC_PATTERNS = [
    re.compile(r"dnssec\s*=\s*['\"]?enable", re.IGNORECASE),
    re.compile(r"dnssec-validation", re.IGNORECASE),
    re.compile(r"SignedZone|signed-zone", re.IGNORECASE),
]

_CAA_RECORD_PATTERNS = [
    re.compile(r"CAA|caa_record", re.IGNORECASE),
]

_SUBDOMAIN_TAKEOVER_PATTERNS = [
    (re.compile(r"CNAME\s+\S+\.(amazonaws\.com|azurewebsites\.net|herokuapp\.com|github\.io|surge\.sh|bitbucket\.io|ghost\.io)", re.IGNORECASE),
     "Potential dangling CNAME to third-party service"),
    (re.compile(r"ALIAS\s+\S+\.(amazonaws\.com|azurewebsites\.net|herokuapp\.com)", re.IGNORECASE),
     "Potential dangling ALIAS to third-party service"),
]


_log = logging.getLogger("patchi.security.dns_security_agent")


@register
class DNSSecurityAgent(BaseAgent):
    """Agent for detecting DNS security issues."""

    group = AgentGroup.SECURITY
    name = "DNSSecurityAgent"
    description = "DNS security: dangling records, zone transfer, DNSSEC, CAA records"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings: list[Finding] = []
        files_scanned = 0

        with trace_agent(self.name, inp.root) as trace:
            # ── Static analysis ────────────────────────────────────────────
            findings.extend(self._scan_dns_configs(inp))
            findings.extend(self._scan_zone_transfer(inp))
            findings.extend(self._scan_dnssec(inp))
            findings.extend(self._scan_caa_records(inp))
            findings.extend(self._scan_terraform_route53(inp))
            findings.extend(self._scan_subdomain_takeover(inp))

            for pattern in _SOURCE_EXTENSIONS:
                for fp in safe_rglob(inp.root, pattern):
                    if fp.is_file():
                        files_scanned += 1
                        findings.extend(self._scan_file(fp, inp.root))

            # ── External tools ─────────────────────────────────────────────
            if shutil.which("dig"):
                findings.extend(self._run_dig_checks(inp))
            if shutil.which("dnsReaper") or shutil.which("dnsreaper"):
                findings.extend(self._run_dnsreaper(inp))

            trace.findings = len(findings)
            trace.files_scanned = files_scanned

        result.status = AgentStatus.SUCCEEDED
        result.findings = findings
        result.data.update({
            "dns_findings": len(findings),
            "dig_available": shutil.which("dig") is not None,
            "dnsreaper_available": shutil.which("dnsReaper") is not None or shutil.which("dnsreaper") is not None,
        })
        return

    # ── DNS config file scan ───────────────────────────────────────────────

    def _scan_dns_configs(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for fp in safe_rglob(inp.root, "*"):
            if fp.name in _DNS_CONFIG_NAMES or fp.name.startswith("db."):
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    if "dnssec" not in content.lower():
                        findings.append(make_finding(
                            severity=Severity.MEDIUM,
                            file=rel,
                            line_start=0,
                            title="DNS-03: DNSSEC Not Configured",
                            description="DNS zone file found without DNSSEC signing configuration.",
                            suggestion="Enable DNSSEC to prevent DNS spoofing and cache poisoning.",
                        ))
                    if "CAA" not in content:
                        findings.append(make_finding(
                            severity=Severity.MEDIUM,
                            file=rel,
                            line_start=0,
                            title="DNS-04: No CAA Records Found",
                            description="No CAA (Certification Authority Authorization) records found in zone file.",
                            suggestion="Add CAA records to restrict certificate issuance to authorized CAs.",
                        ))
                except Exception as e:
                    _log.warning("DNSSecurityAgent._scan_dns_configs failed: %s", e)
        return findings

    # ── Zone transfer protection ───────────────────────────────────────────

    def _scan_zone_transfer(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.conf", "*.cfg", "*.tf", "*.yaml", "*.yml"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        for rx, desc in _ZONE_TRANSFER_PATTERNS:
                            if rx.search(line):
                                severity = Severity.HIGH if "any" in line.lower() else Severity.MEDIUM
                                findings.append(make_finding(
                                    severity=severity,
                                    file=rel,
                                    line_start=i,
                                    title="DNS-01: Zone Transfer Risk",
                                    description=desc,
                                    evidence=line.strip(),
                                    suggestion="Restrict zone transfers to authorized secondaries only.",
                                ))
                                break
                except Exception as e:
                    _log.warning("DNSSecurityAgent._scan_zone_transfer failed: %s", e)
        return findings

    # ── DNSSEC configuration ───────────────────────────────────────────────

    def _scan_dnssec(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.conf", "*.tf", "*.yaml", "*.yml", "*.json"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    has_dnssec = any(rx.search(content) for rx in _DNSSEC_PATTERNS)
                    if not has_dnssec and any(k in content.lower() for k in ("zone", "dns", "route53")):
                        findings.append(make_finding(
                            severity=Severity.MEDIUM,
                            file=rel,
                            line_start=0,
                            title="DNS-03: DNSSEC Not Enabled",
                            description="DNS configuration found without DNSSEC validation.",
                            suggestion="Enable DNSSEC validation to prevent DNS spoofing.",
                        ))
                except Exception as e:
                    _log.warning("DNSSecurityAgent._scan_dnssec failed: %s", e)
        return findings

    # ── CAA records ────────────────────────────────────────────────────────

    def _scan_caa_records(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.tf", "*.yaml", "*.yml", "*.json", "*.conf"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    if any(k in content.lower() for k in ("zone", "dns", "domain", "route53")):
                        has_caa = any(rx.search(content) for rx in _CAA_RECORD_PATTERNS)
                        if not has_caa:
                            findings.append(make_finding(
                                severity=Severity.MEDIUM,
                                file=rel,
                                line_start=0,
                                title="DNS-04: No CAA Records",
                                description="DNS zone configuration has no CAA records to restrict certificate issuance.",
                                suggestion="Add CAA records (e.g., 0 issue \"letsencrypt.org\").",
                            ))
                except Exception as e:
                    _log.warning("DNSSecurityAgent._scan_caa_records failed: %s", e)
        return findings

    # ── Terraform Route53 ──────────────────────────────────────────────────

    def _scan_terraform_route53(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for fp in safe_rglob(inp.root, "*.tf"):
            if not fp.is_file():
                continue
            rel = fp.relative_to(inp.root).as_posix()
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
                has_route53 = any(rx.search(content) for rx in _ROUTE53_PATTERNS)
                if has_route53:
                    if "enable_dnssec" not in content.lower():
                        findings.append(make_finding(
                            severity=Severity.MEDIUM,
                            file=rel,
                            line_start=0,
                            title="DNS-03: Route53 Zone Without DNSSEC",
                            description="Terraform Route53 zone does not enable DNSSEC.",
                            suggestion="Set enable_dnssec = true on aws_route53_zone.",
                        ))
                    if "caa" not in content.lower() and "record" in content.lower():
                        findings.append(make_finding(
                            severity=Severity.MEDIUM,
                            file=rel,
                            line_start=0,
                            title="DNS-04: Route53 Without CAA Records",
                            description="Route53 records found but no CAA record defined.",
                            suggestion="Add an aws_route53_record of type CAA.",
                        ))
                    if "allow_transfer" not in content.lower() and "zone" in content.lower():
                        findings.append(make_finding(
                            severity=Severity.LOW,
                            file=rel,
                            line_start=0,
                            title="DNS-05: Route53 Zone Transfer Not Configured",
                            description="Route53 zone found without explicit transfer restrictions.",
                            suggestion="Ensure zone transfer is restricted or disabled.",
                        ))
            except Exception as e:
                _log.warning("DNSSecurityAgent._scan_terraform_route53 failed: %s", e)
        return findings

    # ── Subdomain takeover patterns ────────────────────────────────────────

    def _scan_subdomain_takeover(self, inp: AgentInput) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in ("*.tf", "*.yaml", "*.yml", "*.json", "*.conf", "*.db"):
            for fp in safe_rglob(inp.root, pattern):
                if not fp.is_file():
                    continue
                rel = fp.relative_to(inp.root).as_posix()
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")
                    lines = content.splitlines()
                    for i, line in enumerate(lines, 1):
                        for rx, desc in _SUBDOMAIN_TAKEOVER_PATTERNS:
                            if rx.search(line):
                                findings.append(make_finding(
                                    severity=Severity.HIGH,
                                    file=rel,
                                    line_start=i,
                                    title="DNS-02: Potential Subdomain Takeover",
                                    description=desc,
                                    evidence=line.strip(),
                                    suggestion="Verify the target service is claimed and not vulnerable to takeover.",
                                ))
                except Exception as e:
                    _log.warning("DNSSecurityAgent._scan_subdomain_takeover failed: %s", e)
        return findings

    # ── General source file scan ───────────────────────────────────────────

    def _scan_file(self, fp: Path, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        rel = fp.relative_to(root).as_posix()
        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
            # DNS-related hardcoded secrets
            secret_patterns = [
                (re.compile(r"(?:route53|dns|cloudflare)[_-]?(?:api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE),
                 "DNS-06: Hardcoded DNS/CDN API Credential"),
            ]
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                for rx, title in secret_patterns:
                    if rx.search(line):
                        findings.append(make_finding(
                            severity=Severity.CRITICAL,
                            file=rel,
                            line_start=i,
                            title=title,
                            description="Hardcoded DNS API credential found in source code.",
                            evidence=line.strip()[:120],
                            suggestion="Move DNS API credentials to environment variables or a secrets manager.",
                        ))
        except Exception as e:
            _log.warning("DNSSecurityAgent._scan_file failed: %s", e)
        return findings

    # ── External tool: dig ─────────────────────────────────────────────────

    def _run_dig_checks(self, inp: AgentInput) -> list[Finding]:
        """Run dig to check DNS records if a domain is provided."""
        findings: list[Finding] = []
        domain = inp.config.get("dns_check_domain")
        if not domain or not isinstance(domain, str):
            return findings

        # Check for zone transfer vulnerability
        try:
            proc = subprocess.run(
                ["dig", "axfr", domain, "+short", "+timeout=5"],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                findings.append(make_finding(
                    severity=Severity.CRITICAL,
                    file="(dns_probe)",
                    line_start=0,
                    title="DNS-01: Zone Transfer Allowed",
                    description=f"DNS zone transfer (AXFR) succeeded for {domain}.",
                    evidence=proc.stdout[:300],
                    suggestion="Restrict zone transfers to authorized secondaries.",
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Check for DNSSEC
        try:
            proc = subprocess.run(
                ["dig", "+dnssec", domain, "+short", "+timeout=5"],
                capture_output=True, text=True, timeout=10,
            )
            if proc.returncode == 0 and "RRSIG" not in proc.stdout:
                findings.append(make_finding(
                    severity=Severity.MEDIUM,
                    file="(dns_probe)",
                    line_start=0,
                    title="DNS-03: DNSSEC Not Active",
                    description=f"No DNSSEC RRSIG records found for {domain}.",
                    evidence=proc.stdout[:200],
                    suggestion="Enable DNSSEC signing for the domain.",
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return findings

    # ── External tool: dnsReaper ───────────────────────────────────────────

    def _run_dnsreaper(self, inp: AgentInput) -> list[Finding]:
        """Run dnsReaper for subdomain takeover detection."""
        findings: list[Finding] = []
        domain = inp.config.get("dns_check_domain")
        if not domain or not isinstance(domain, str):
            return findings

        tool = "dnsReaper" if shutil.which("dnsReaper") else "dnsreaper"
        try:
            proc = subprocess.run(
                [tool, "scan", "--domain", domain, "--output", "json"],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                import json
                try:
                    data = json.loads(proc.stdout)
                    for record in data if isinstance(data, list) else []:
                        if record.get("vulnerable"):
                            findings.append(make_finding(
                                severity=Severity.HIGH,
                                file="(dnsreaper)",
                                line_start=0,
                                title="DNS-06: Subdomain Takeover Vulnerability",
                                description=f"Subdomain {record.get('subdomain', 'unknown')} is vulnerable to takeover.",
                                evidence=str(record)[:200],
                                suggestion="Remove the dangling record or claim the target resource.",
                            ))
                except json.JSONDecodeError:
                    pass
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return findings
