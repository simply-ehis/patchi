"""SAML/SSO security agent — validates SAML implementations against known attack patterns."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

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
    safe_rglob,
)
from ..brain.trace_log import trace_agent

# SAML library detection patterns
SAML_LIBRARIES = {
    "pysaml2": {
        "import": r"from\s+saml2\b|import\s+saml2\b",
        "config": r"saml2\.config|SPConfig|IdPConfig",
    },
    "onelogin": {
        "import": r"from\s+onelogin\.saml2\b|import\s+onelogin\.saml2\b",
        "auth": r"OneLogin_Saml2_Auth|AuthnRequest",
    },
    "python3-saml": {
        "import": r"from\s+onelogin\.saml2\b|import\s+onelogin\.saml2\b",
        "settings": r"saml_settings|SAML_SETTINGS",
    },
    "lxml-saml": {
        "import": r"from\s+lxml\.etree\b|import\s+lxml\.etree\b",
        "etree": r"etree\.fromstring|etree\.parse|etree\.XML",
    },
}

# Dangerous XML patterns (XXE, XSW).
# Part 7: only INSECURE-CONFIG literals and external-scheme references
# verdict here. Bare "ENTITY"/"entity" matches entity_id/EntityDescriptor;
# generic DOM ops (cloneNode etc.) are demoted at emit time. Each entry is
# (pattern, description, severity).
XXE_PATTERNS = [
    (r"resolve_entities\s*=\s*True", "XML entity resolution enabled", Severity.CRITICAL),
    (r"no_network\s*=\s*False", "Network access during XML parsing", Severity.CRITICAL),
    (r"DTDLOAD|dtd_load|load_dtd", "DTD loading enabled", Severity.CRITICAL),
    # Custom entity DECLARATIONS only (predefined amp/lt/gt/quot/apos
    # excluded), and SYSTEM references with an external scheme — the XXE
    # vector itself.
    (
        r"<!ENTITY\s+(?!%\s*(?:amp|lt|gt|quot|apos)\b)(?!\s*(?:amp|lt|gt|quot|apos)\b)[^>]+>",
        "Custom XML entity declaration",
        Severity.MEDIUM,
    ),
    (r"SYSTEM\s+[\"'](?:https?|file|ftp|php|expect|data):", "External SYSTEM entity reference", Severity.HIGH),
]

XSW_PATTERNS = [
    # Part 7: generic DOM manipulation is MEDIUM + verify, not CRITICAL XSW.
    (r"cloneNode|importNode", "DOM node cloning near signatures — verify no signature bypass", Severity.MEDIUM),
    (r"insertBefore.*Signature", "XML Signature Wrapping — insert before signature", Severity.MEDIUM),
    (r"getElementById.*Signature", "XML Signature Wrapping — ID reference", Severity.MEDIUM),
]

SIGNATURE_VALIDATION_PATTERNS = [
    (
        r"check_signature|validate_signature|verify_signature|isValidSignature",
        "Signature validation present",
    ),
    (r"assertion.*valid|validate.*assertion", "Assertion validation"),
    (r"SignedInfo|Reference.*URI.*DigestValue", "XML signature structure detected"),
]

ASSERTION_LIFETIME_PATTERNS = [
    (r"NotBefore|NotOnOrAfter", "Assertion time bounds present"),
    (r"SessionIndex|session_not_on_or_after", "Session index tracking"),
    (r"clock_slop|clockSkew|ALLOWED_CLOCK_SKEW", "Clock skew tolerance configured"),
]

RELAYSTATE_PATTERNS = [
    (r"RelayState|relay_state", "RelayState handling detected"),
    (r"redirect.*url|return.*url|target.*url", "Redirect URL handling"),
]

CONTROL_IDS = {
    "SAML-01": ("SAML XXE in XML parsing", Severity.CRITICAL),
    "SAML-02": ("XML Signature Wrapping attack vector", Severity.CRITICAL),
    "SAML-03": ("Weak algorithm enforcement (SHA-1)", Severity.HIGH),
    "SAML-04": ("Missing signature validation", Severity.HIGH),
    "SAML-05": ("No assertion lifetime enforcement", Severity.HIGH),
    "SAML-06": ("RelayState open redirect", Severity.MEDIUM),
    "SAML-07": ("SAML library in use", Severity.INFO),
    "SAML-08": ("Assertion replay protection missing", Severity.HIGH),
    "SAML-09": ("Certificate trust not pinned", Severity.MEDIUM),
}


_log = logging.getLogger("patchi.security.saml_sso_agent")


@register
class SamlSSOAgent(BaseAgent):
    name = "SamlSSOAgent"
    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    description = "SAML/SSO security: XSW, XXE, algorithm enforcement, assertion replay, certificate trust"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        with trace_agent(self.name, inp.root) as trace:
            findings: list[Finding] = []
            files_scanned = 0

            # Phase 1: Static analysis of source code
            for fpath in safe_rglob(inp.root, "*.py"):
                files_scanned += 1
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    _log.warning("SamlSSOAgent._run failed: %s", e)
                    continue

                rel = str(fpath.relative_to(inp.root))

                # Detect SAML library usage
                for lib_name, lib_patterns in SAML_LIBRARIES.items():
                    for pattern_key, pattern in lib_patterns.items():
                        for m in re.finditer(pattern, content, re.IGNORECASE):
                            line_no = content[: m.start()].count("\n") + 1
                            findings.append(
                                make_finding(
                                    Severity.INFO,
                                    rel,
                                    line_no,
                                    f"SAML library detected: {lib_name}",
                                    f"Code uses {lib_name} library ({pattern_key} pattern). Verify SAML security"
                                    f" configuration.",
                                    code_snippet=m.group(),
                                    suggestion=f"Review {lib_name} configuration for security best practices",
                                    control_id="SAML-07",
                                )
                            )

                # Check for XXE patterns (severity rides with the pattern)
                for pattern, desc, sev in XXE_PATTERNS:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        line_no = content[: m.start()].count("\n") + 1
                        findings.append(
                            make_finding(
                                sev,
                                rel,
                                line_no,
                                "SAML-01: XML External Entity (XXE) vulnerability",
                                desc,
                                code_snippet=m.group(),
                                suggestion="Disable DTD loading and entity resolution in XML parser",
                                cwe="CWE-611",
                                control_id="SAML-01",
                            )
                        )

                # Check for XSW patterns (severity rides with the pattern)
                for pattern, desc, sev in XSW_PATTERNS:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        line_no = content[: m.start()].count("\n") + 1
                        findings.append(
                            make_finding(
                                sev,
                                rel,
                                line_no,
                                "SAML-02: XML Signature Wrapping attack vector",
                                desc,
                                code_snippet=m.group(),
                                suggestion="Use a SAML library that prevents Signature Wrapping attacks",
                                cwe="CWE-327",
                                control_id="SAML-02",
                            )
                        )

                # Check for weak algorithms (SHA-1). Part 7: bound to
                # digest/signature context — a bare "sha1" anywhere (UUIDs,
                # comments, test names) is not a SAML finding.
                _DIGEST_CTX = re.compile(r"digest|signature|saml|assertion|algorithm|hash", re.IGNORECASE)
                for m in re.finditer(r"sha-?1|md5", content, re.IGNORECASE):
                    line_no = content[: m.start()].count("\n") + 1
                    line_text = content.splitlines()[line_no - 1] if line_no <= len(content.splitlines()) else ""
                    if not _DIGEST_CTX.search(line_text):
                        continue
                    findings.append(
                        make_finding(
                            Severity.HIGH,
                            rel,
                            line_no,
                            "SAML-03: Weak cryptographic algorithm (SHA-1/MD5)",
                            "SAML assertion uses deprecated hash algorithm. SHA-1 is vulnerable to collision"
                            " attacks.",
                            code_snippet=m.group(),
                            suggestion="Upgrade to SHA-256 or stronger algorithms",
                            cwe="CWE-327",
                            control_id="SAML-03",
                        )
                    )

                # Library-aware absence checks (Part 7): pysaml2/one-login
                # validate signatures/lifetimes by default — flagging their
                # absence in a file that delegates to them is a false
                # positive. Only verdict when the file parses SAML itself.
                _lib_import = any(
                    re.search(p, content) for p in (
                        r"from\s+onelogin\.saml2\b", r"import\s+onelogin\.saml2\b",
                        r"from\s+saml2\b", r"import\s+saml2\b",
                    )
                )
                _custom_xml = bool(
                    re.search(r"etree\.(fromstring|parse|XML)|lxml|xml\.dom|ElementTree", content)
                )

                # Check for missing signature validation
                has_sig_validation = any(re.search(p, content, re.IGNORECASE) for p, _ in SIGNATURE_VALIDATION_PATTERNS)
                if (
                    re.search(r"saml2?\b|onelogin|AuthnRequest|SAMLResponse", content, re.IGNORECASE)
                    and not has_sig_validation
                    and not (_lib_import and not _custom_xml)
                ):
                    findings.append(
                        make_finding(
                            Severity.HIGH,
                            rel,
                            0,
                            "SAML-04: Missing signature validation",
                            "SAML processing code detected without signature validation. Assertions may be forged.",
                            suggestion="Implement XML signature validation before processing assertions",
                            cwe="CWE-347",
                            control_id="SAML-04",
                        )
                    )

                # Check for assertion lifetime
                has_lifetime = any(re.search(p, content, re.IGNORECASE) for p, _ in ASSERTION_LIFETIME_PATTERNS)
                if (
                    re.search(r"saml2?\b|assertion|SAMLResponse", content, re.IGNORECASE)
                    and not has_lifetime
                    and not (_lib_import and not _custom_xml)
                ):
                    findings.append(
                        make_finding(
                            Severity.HIGH,
                            rel,
                            0,
                            "SAML-05: No assertion lifetime enforcement",
                            "SAML assertions processed without checking NotBefore/NotOnOrAfter. Replay attacks"
                            " possible.",
                            suggestion="Enforce assertion time bounds and session index tracking",
                            cwe="CWE-294",
                            control_id="SAML-05",
                        )
                    )

                # Check for RelayState validation
                has_relay = any(re.search(p, content, re.IGNORECASE) for p, _ in RELAYSTATE_PATTERNS)
                if has_relay:
                    # Check if validation is present
                    if not re.search(
                        r"whitelist|allowlist|validate.*relay|check.*relay|sanitize.*relay",
                        content,
                        re.IGNORECASE,
                    ):
                        findings.append(
                            make_finding(
                                Severity.MEDIUM,
                                rel,
                                0,
                                "SAML-06: RelayState open redirect potential",
                                "RelayState parameter used without explicit validation. May allow open redirect"
                                " attacks.",
                                suggestion="Validate RelayState against an allowlist of permitted redirect URLs",
                                cwe="CWE-601",
                                control_id="SAML-06",
                            )
                        )

                # Check for assertion replay protection (same library rule:
                # delegated-to-library files are not verdicts).
                if re.search(r"saml2?\b|SAMLResponse", content, re.IGNORECASE):
                    if not re.search(r"SessionIndex|session_index|replay|nonce|jti", content, re.IGNORECASE):
                        if not (_lib_import and not _custom_xml):
                            findings.append(
                                make_finding(
                                    Severity.HIGH,
                                    rel,
                                    0,
                                    "SAML-08: Assertion replay protection missing",
                                    "No session index or nonce tracking detected. SAML assertions may be replayed.",
                                    suggestion="Track assertion IDs and session indices to prevent replay attacks",
                                    cwe="CWE-294",
                                    control_id="SAML-08",
                                )
                            )

                # Check for certificate trust pinning
                if re.search(r"certificate|cert|X509|trust", content, re.IGNORECASE):
                    if not re.search(
                        r"pin|trust_store|ca_bundle|certificate_file|verify.*cert",
                        content,
                        re.IGNORECASE,
                    ):
                        findings.append(
                            make_finding(
                                Severity.MEDIUM,
                                rel,
                                0,
                                "SAML-09: Certificate trust not pinned",
                                "SAML certificate handling without explicit trust pinning. May accept forged"
                                " certificates.",
                                suggestion="Pin IdP certificate or use a trusted CA bundle for validation",
                                cwe="CWE-295",
                                control_id="SAML-09",
                            )
                        )

            # Phase 2: Scan YAML/JSON configs for SAML metadata
            for fpath in safe_rglob(inp.root, "*.xml"):
                files_scanned += 1
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception as e:
                    _log.warning("SamlSSOAgent._run failed: %s", e)
                    continue

                rel = str(fpath.relative_to(inp.root))

                # Check for SAML metadata files
                if re.search(r"EntityDescriptor|SPSSODescriptor|IDPSSODescriptor", content):
                    # Check for SHA-1 in metadata
                    if re.search(r"SHA-1|sha1|DigestMethod.*SHA-1", content):
                        findings.append(
                            make_finding(
                                Severity.HIGH,
                                rel,
                                0,
                                "SAML-03: Weak algorithm in SAML metadata",
                                "SAML metadata specifies SHA-1 digest method. Upgrade to SHA-256.",
                                suggestion="Update DigestMethod and SignatureMethod to SHA-256 or stronger",
                                cwe="CWE-327",
                                control_id="SAML-03",
                            )
                        )

                    # Check for WantAssertionsSigned
                    if re.search(r"WantAssertionsSigned\s*=\s*[\"']false[\"']", content):
                        findings.append(
                            make_finding(
                                Severity.HIGH,
                                rel,
                                0,
                                "SAML-04: Assertions not required to be signed",
                                "WantAssertionsSigned=false allows unsigned assertions. Forged assertions accepted.",
                                suggestion="Set WantAssertionsSigned=true in SP metadata",
                                cwe="CWE-347",
                                control_id="SAML-04",
                            )
                        )

            # Phase 3: Try external SAST tools (semgrep has SAML rules)
            semgrep_path = shutil.which("semgrep")
            if semgrep_path:
                from .security_config import _semgrep_config_value

                semgrep_config = _semgrep_config_value(inp.root)
                if not semgrep_config:
                    semgrep_path = None  # offline + no local pack -> skip
            if semgrep_path:
                try:
                    proc = subprocess.run(
                        [
                            semgrep_path,
                            "--config",
                            semgrep_config,
                            "--include",
                            "*.py",
                            "--json",
                            "--quiet",
                            str(inp.root),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    if proc.returncode == 0 and proc.stdout:
                        import json

                        try:
                            # Part 7: semgrep's own severity, not rule-name
                            # substring matching ("xml" fires on xmltodict).
                            _sem_sev = {
                                "ERROR": Severity.HIGH,
                                "WARNING": Severity.MEDIUM,
                                "INFO": Severity.LOW,
                            }
                            data = json.loads(proc.stdout)
                            for r in data.get("results", []):
                                rule_id = r.get("check_id", "")
                                sev = _sem_sev.get(
                                    str(r.get("extra", {}).get("severity", "")).upper(),
                                    Severity.MEDIUM,
                                )
                                findings.append(
                                    make_finding(
                                        sev,
                                        r.get("path", ""),
                                        r.get("start", {}).get("line", 0),
                                        f"Semgrep: {rule_id}",
                                        r.get("extra", {}).get("message", ""),
                                        code_snippet=r.get("extra", {}).get("lines", ""),
                                        suggestion="Review semgrep finding for SAML security impact",
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
