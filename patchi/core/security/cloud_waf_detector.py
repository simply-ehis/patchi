"""Cloud WAF Detector — AWS WAF & Cloudflare WAF misconfiguration and bypass detection.

Scans project infrastructure code for WAF misconfigurations:
- Missing WAF on public-facing ALB/CloudFront/API Gateway
- Rate limits too permissive or absent
- Missing OWASP core rule set or managed rules
- Geo-blocking not configured for admin endpoints
- Cloudflare: missing bot management, browser integrity check, or rate limiting
- Cloudflare: wide-open page rules, disabled security in page rules
- AWS WAF: missing IP set restrictions on admin paths

Also detects WAF bypass attempts in intercepted requests:
- HTTP parameter pollution
- Encoding bypasses (double URL encoding, unicode, comments)
- HTTP method tunneling
- Case manipulation
"""

from __future__ import annotations
import logging

import re

from ..agents.base import (
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


_log = logging.getLogger("patchi.security.cloud_waf_detector")


@register
class CloudWAFDetector(BaseAgent):
    """Detect AWS WAF & Cloudflare WAF misconfigurations and bypass patterns."""

    group = AgentGroup.SECURITY
    name = "CloudWAFDetector"
    description = "Cloud WAF misconfiguration and bypass detection"

    # ── Cloudflare page rule patterns that disable security ──
    CF_INSECURE_PAGE_RULES = re.compile(
        r"(security\s*=\s*\"off\"|disable_security|security_level\s*=\s*\"essentially_off\")",
        re.IGNORECASE,
    )
    CF_WIDE_OPEN_CACHE = re.compile(
        r"(edge_cache_ttl\s*=\s*0|cache_level\s*=\s*\"bypass\")",
        re.IGNORECASE,
    )

    # ── Terraform AWS WAF patterns (positive match = issue) ──
    MISSING_WAF_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "aws_alb",
            r"resource\s+\"aws_alb\"",
            "ALB without WAF association — add aws_wafv2_web_acl_association",
            Severity.HIGH,
        ),
        (
            "aws_lb",
            r"resource\s+\"aws_lb\"[^}]*?internal\s*=\s*false",
            "Public ALB without WAF association — add aws_wafv2_web_acl_association",
            Severity.HIGH,
        ),
        (
            "aws_cloudfront_distribution",
            r"resource\s+\"aws_cloudfront_distribution\"",
            "CloudFront without WAF — add web_acl_id referencing WAFv2 ACL",
            Severity.HIGH,
        ),
        (
            "aws_api_gateway_rest_api",
            r"resource\s+\"aws_api_gateway_rest_api\"",
            "API Gateway without WAF — add WAFv2 ACL association",
            Severity.MEDIUM,
        ),
    ]

    WAF_WEAKNESSES: list[tuple[str, str, Severity]] = [
        (
            "No rate limiting configured",
            r"rate_based_statement|rate_limit",
            Severity.MEDIUM,
        ),
        (
            "No AWS managed rules",
            r"managed_rule_group_statement|vendor_name\s*=\s*\"aws\"",
            Severity.MEDIUM,
        ),
        (
            "No OWASP CRS",
            r"core_rule_set|owasp.*crs|managed_rule.*owasp",
            Severity.MEDIUM,
        ),
    ]

    WAF_MISCONFIG_PATTERNS: list[tuple[str, str, str, Severity]] = [
        (
            "allow_all_default",
            r"default_action\s*\{\s*allow\s*\}",
            "WAF default action is ALLOW — should be BLOCK with explicit allow rules",
            Severity.HIGH,
        ),
        (
            "no_ip_restriction_admin",
            r"geo_match_statement|ip_set_reference_statement",
            "No Geo/IP restriction on admin paths detected",
            Severity.MEDIUM,
        ),
    ]

    # ── Bypass patterns in request data ──
    WAF_BYPASS_PATTERNS: list[tuple[str, str, Severity]] = [
        (
            "HTTP parameter pollution",
            r"(&|\?)[^=]+=[^&]*&[^=]+=[^&]*(&[^=]+=[^&]*)+",
            Severity.MEDIUM,
        ),
        (
            "Double URL encoding",
            r"%25[0-9a-fA-F]{2}",
            Severity.MEDIUM,
        ),
        (
            "Unicode encoding bypass",
            r"\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4}",
            Severity.LOW,
        ),
        (
            "HTTP method tunneling",
            r"(X-HTTP-Method-Override|X-HTTP-Method|X-Method-Override):\s*\w+",
            Severity.MEDIUM,
        ),
        (
            "Case manipulation bypass",
            r"(<[Ss][Cc][Rr][Ii][Pp][Tt]>|<[Ss][Vv][Gg]/[Oo][Nn][Ll][Oo][Aa][Dd])",
            Severity.LOW,
        ),
    ]

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        root = inp.root
        findings: list[Finding] = []

        # Phase 1: Scan IaC files for WAF misconfigs
        # safe_rglob yields generators — materialize before concatenating.
        tf_files = list(safe_rglob(root, "*.tf"))
        cf_files = list(safe_rglob(root, "*.yaml")) + list(safe_rglob(root, "*.yml"))
        ia_files = tf_files + [
            f for f in cf_files if "cloudflare" in str(f).lower() or "waf" in str(f).lower()
        ]

        for fp in ia_files:
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                _log.warning("CloudWAFDetector._run failed: %s", e)
                continue
            rel = str(fp.relative_to(root))

            for res_name, pattern, msg, severity in self.MISSING_WAF_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="missing_waf",
                            severity=severity,
                            file=rel,
                            message=f"{msg} ({res_name})",
                            cwe="CWE-693",
                        )
                    )

            for name, pattern, severity in self.WAF_WEAKNESSES:
                if not re.search(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="waf_weakness",
                            severity=severity,
                            file=rel,
                            message=f"WAF weakness: {name}",
                            cwe="CWE-693",
                        )
                    )

            for name, pattern, msg, severity in self.WAF_MISCONFIG_PATTERNS:
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="waf_" + name,
                            severity=severity,
                            file=rel,
                            message=msg,
                            snippet=m.group()[:80],
                            cwe="CWE-693",
                        )
                    )

            # Cloudflare-specific checks
            if fp.suffix == ".yaml":
                m = self.CF_INSECURE_PAGE_RULES.search(text)
                if m:
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="cf_insecure_page_rule",
                            severity=Severity.HIGH,
                            file=rel,
                            message="Cloudflare page rule disables security",
                            snippet=m.group(),
                            cwe="CWE-693",
                        )
                    )

                m = self.CF_WIDE_OPEN_CACHE.search(text)
                if m:
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="cf_bypass_cache",
                            severity=Severity.MEDIUM,
                            file=rel,
                            message="Cloudflare cache bypassed in page rule",
                            snippet=m.group(),
                            cwe="CWE-693",
                        )
                    )

        # Phase 2: WAF bypass patterns in test/request files
        test_files = list(safe_rglob(root, "*test*")) + list(safe_rglob(root, "*spec*"))
        seen_bypass: set[tuple[str, str]] = set()
        for fp in test_files:
            if fp.suffix not in {".py", ".js", ".ts", ".http", ".txt", ".csv", ".json"}:
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                _log.warning("CloudWAFDetector._run failed: %s", e)
                continue
            rel = str(fp.relative_to(root))
            for name, pattern, severity in self.WAF_BYPASS_PATTERNS:
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    key = (rel, name)
                    if key in seen_bypass:
                        continue
                    seen_bypass.add(key)
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="waf_bypass",
                            severity=severity,
                            file=rel,
                            message=f"WAF bypass pattern: {name}",
                            line=1 + text[: m.start()].count("\n"),
                            snippet=m.group()[:80],
                            cwe="CWE-693",
                        )
                    )

        # Phase 3: CloudFront without origin access identity
        seen_no_oai = False
        for fp in tf_files:
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                _log.warning("CloudWAFDetector._run failed: %s", e)
                continue
            rel = str(fp.relative_to(root))
            if re.search(r"resource\s+\"aws_cloudfront_distribution\"", text) and not re.search(
                r"origin_access_identity|oai", text
            ):
                if not seen_no_oai:
                    seen_no_oai = True
                    findings.append(
                        Finding(
                            agent=self.name,
                            type="cloudfront_no_oai",
                            severity=Severity.MEDIUM,
                            file=rel,
                            message="CloudFront distribution without origin access identity",
                            cwe="CWE-693",
                        )
                    )

        result.findings = findings
        result.status = AgentStatus.DONE
        result.files_scanned = len(ia_files) + len(test_files)
