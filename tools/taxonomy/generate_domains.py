#!/usr/bin/env python3
"""
Patchi Security Domain Generator — Creates 800 comprehensive security domains
and their matching playbooks from OWASP, CWE, NIST, SANS, MITRE ATT&CK,
CIS, PCI DSS, HIPAA, SOC 2, GDPR, ISO 27001, and technology-specific sources.

Outputs:
  <patchi-root>/core/security/domains/<id>.yaml
  <patchi-root>/core/security/fix-playbooks/<id>.playbook.yaml

Usage (from anywhere):
  python tools/taxonomy/generate_domains.py               # regenerate in-repo
  python tools/taxonomy/generate_domains.py --out DEST    # write into DEST

DEST defaults to the repository root (parent of tools/). Inside DEST the
patchi/core/security/{domains,fix-playbooks} layout is created. When neither
exists yet (e.g. a DEST scratch dir), the files land directly under
DEST/domains and DEST/fix-playbooks.
"""
from pathlib import Path

DOMAINS_DIR = Path("patchi/core/security/domains")
PLAYBOOKS_DIR = Path("patchi/core/security/fix-playbooks")

# ══════════════════════════════════════════════════════════════════════════════
# DOMAIN DEFINITIONS — 800 security domains across all frameworks
# Each tuple: (domain_id, display_name, source_standard, component_type,
#              weight, source_clause, description, severity, check_method)
# ══════════════════════════════════════════════════════════════════════════════

DOMAINS = []

def d(did, name, source, ctype, weight, clause, desc, sev="high", check="static"):
    DOMAINS.append((did, name, source, ctype, weight, clause, desc, sev, check))

# ── OWASP Top 10 2021 ────────────────────────────────────────────────────────
d("owasp-a01-broken-access-control", "Broken Access Control", "OWASP Top 10 2021 A01", "backend-api", 0.95, "OWASP A01:2021", "Unauthorized access to resources or functions beyond intended permissions. Includes IDOR, privilege escalation, CORS misconfig, and missing function-level access checks.", "high", "static+dynamic")
d("owasp-a02-cryptographic-failures", "Cryptographic Failures", "OWASP Top 10 2021 A02", "backend-api", 0.95, "OWASP A02:2021", "Failures related to cryptography which often lead to exposure of sensitive data. Includes weak algorithms, improper key management, and insufficient encryption.", "high", "static")
d("owasp-a03-injection", "Injection", "OWASP Top 10 2021 A03", "backend-api", 0.95, "OWASP A03:2021", "User-supplied data is not validated, filtered, or sanitized. Includes SQL, NoSQL, OS command, LDAP, and XSS injection.", "critical", "static+dynamic")
d("owasp-a04-insecure-design", "Insecure Design", "OWASP Top 10 2021 A04", "backend-api", 0.85, "OWASP A04:2021", "Risks related to design flaws, missing or ineffective security architecture. Missing threat modeling and secure design patterns.", "high", "manual-review")
d("owasp-a05-security-misconfiguration", "Security Misconfiguration", "OWASP Top 10 2021 A05", "infra", 0.9, "OWASP A05:2021", "Missing appropriate security hardening across any part of the application stack. Includes default credentials, unnecessary features, and verbose error messages.", "high", "static")
d("owasp-a06-vulnerable-components", "Vulnerable and Outdated Components", "OWASP Top 10 2021 A06", "backend-api", 0.85, "OWASP A06:2021", "Using components with known vulnerabilities, unsupported or out-of-date software.", "high", "static")
d("owasp-a07-auth-failures", "Identification and Authentication Failures", "OWASP Top 10 2021 A07", "backend-api", 0.9, "OWASP A07:2021", "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication attacks.", "high", "static+dynamic")
d("owasp-a08-integrity-failures", "Software and Data Integrity Failures", "OWASP Top 10 2021 A08", "backend-api", 0.85, "OWASP A08:2021", "Code and infrastructure that does not protect against integrity violations. Includes insecure CI/CD pipelines and auto-update without verification.", "high", "static")
d("owasp-a09-logging-monitoring", "Security Logging and Monitoring Failures", "OWASP Top 10 2021 A09", "backend-api", 0.75, "OWASP A09:2021", "Insufficient logging, detection, monitoring, and active response allows attackers to further attack, maintain persistence, and tamper with data.", "medium", "static")
d("owasp-a10-ssrf", "Server-Side Request Forgery", "OWASP Top 10 2021 A10", "backend-api", 0.85, "OWASP A10:2021", "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.", "high", "static+dynamic")

# ── OWASP Top 10 2025 (emerging) ─────────────────────────────────────────────
d("owasp-a01-2025-misconfig", "Security Misconfiguration & Hardening", "OWASP Top 10 2025 A01", "infra", 0.9, "OWASP A01:2025", "Default configurations, unnecessary features, missing security headers, and verbose error handling across the stack.", "high", "static")
d("owasp-a02-2025-crypto", "Cryptographic Failures & Key Management", "OWASP Top 10 2025 A02", "backend-api", 0.95, "OWASP A02:2025", "Weak algorithms, hardcoded keys, improper certificate validation, and insufficient entropy in cryptographic operations.", "critical", "static")
d("owasp-a03-2025-injection", "Injection & Input Handling", "OWASP Top 10 2025 A03", "backend-api", 0.95, "OWASP A03:2025", "SQL, NoSQL, OS command, LDAP, XPath, and template injection via insufficient input validation and parameterization.", "critical", "static+dynamic")
d("owasp-a04-2025-access", "Broken Access Control & Authorization", "OWASP Top 10 2025 A04", "backend-api", 0.95, "OWASP A04:2025", "Privilege escalation, IDOR, missing function-level checks, and JWT validation bypass.", "critical", "static+dynamic")
d("owasp-a05-2025-auth", "Broken Authentication & Session Management", "OWASP Top 10 2025 A05", "backend-api", 0.9, "OWASP A05:2025", "Credential stuffing, brute force, session fixation, and inadequate MFA implementation.", "high", "static+dynamic")
d("owasp-a06-2025-components", "Vulnerable and Outdated Components", "OWASP Top 10 2025 A06", "backend-api", 0.85, "OWASP A06:2025", "Dependencies with known CVEs, unmaintained libraries, and transitive dependency risks.", "high", "static")
d("owasp-a07-2025-integrity", "Software and Data Integrity Failures", "OWASP Top 10 2025 A07", "backend-api", 0.85, "OWASP A07:2025", "Insecure deserialization, unsigned updates, and CI/CD pipeline integrity issues.", "high", "static")
d("owasp-a08-2025-ssrf", "Server-Side Request Forgery (SSRF)", "OWASP Top 10 2025 A08", "backend-api", 0.85, "OWASP A08:2025", "Unvalidated URL fetching leading to internal network access, file reads, or cloud metadata exposure.", "high", "static+dynamic")
d("owasp-a09-2025-logging", "Security Logging & Monitoring Failures", "OWASP Top 10 2025 A09", "backend-api", 0.75, "OWASP A09:2025", "Insufficient logging, missing audit trails, and lack of real-time alerting on security events.", "medium", "static")
d("owasp-a10-2025-ssdlc", "Secure Software Development Lifecycle Failures", "OWASP Top 10 2025 A10", "backend-api", 0.8, "OWASP A10:2025", "Missing threat modeling, insecure design patterns, and lack of security testing in the SDLC.", "high", "manual-review")

# ── OWASP ASVS 5.0 Chapters ──────────────────────────────────────────────────
d("asvs-v1-verification", "Verification Requirements", "OWASP ASVS 5.0 V1", "backend-api", 0.7, "ASVS V1", "Application security requirements documentation, secure development lifecycle, and security architecture documentation.", "medium", "manual-review")
d("asvs-v2-authentication", "Authentication Verification", "OWASP ASVS 5.0 V2", "backend-api", 0.95, "ASVS V2", "Password security, credential storage, multi-factor authentication, and credential recovery mechanisms.", "high", "static+dynamic")
d("asvs-v3-session", "Session Management Verification", "OWASP ASVS 5.0 V3", "backend-api", 0.9, "ASVS V3", "Session token generation, lifecycle management, termination, and protection against session attacks.", "high", "static+dynamic")
d("asvs-v4-access-control", "Access Control Verification", "OWASP ASVS 5.0 V4", "backend-api", 0.95, "ASVS V4", "Authorization enforcement, directory traversal prevention, file and resource access control, and API access restrictions.", "critical", "static+dynamic")
d("asvs-v5-validation", "Validation, Sanitization, and Encoding", "OWASP ASVS 5.0 V5", "backend-api", 0.9, "ASVS V5", "Input validation, output encoding, SQL injection prevention, OS injection prevention, and XSS prevention.", "critical", "static")
d("asvs-v6-crypto", "Cryptography at Rest", "OWASP ASVS 5.0 V6", "backend-api", 0.85, "ASVS V6", "Data encryption at rest, key management, password storage, and random number generation.", "high", "static")
d("asvs-v7-error-handling", "Error Handling and Logging", "OWASP ASVS 5.0 V7", "backend-api", 0.75, "ASVS V7", "Error handling, logging controls, log protection, and error reporting without information leakage.", "medium", "static")
d("asvs-v8-data-protection", "Data Protection", "OWASP ASVS 5.0 V8", "backend-api", 0.85, "ASVS V8", "Data classification, personal data protection, data retention, and privacy controls.", "high", "static+manual-review")
d("asvs-v9-communication", "Communication Security", "OWASP ASVS 5.0 V9", "infra", 0.85, "ASVS V9", "TLS configuration, certificate management, HTTP security headers, and secure communication protocols.", "high", "static")
d("asvs-v10-malicious-code", "Malicious Code Protection", "OWASP ASVS 5.0 V10", "backend-api", 0.8, "ASVS V10", "Anti-malware controls, code integrity verification, and protection against malicious file uploads.", "high", "static+dynamic")
d("asvs-v11-business-logic", "Business Logic", "OWASP ASVS 5.0 V11", "backend-api", 0.85, "ASVS V11", "Business logic abuse prevention, rate limiting, anti-automation, and workflow integrity.", "high", "manual-review")
d("asvs-v12-files-resources", "Files and Resources", "OWASP ASVS 5.0 V12", "backend-api", 0.8, "ASVS V12", "File upload validation, file storage security, file execution prevention, and SSRF protection.", "high", "static")
d("asvs-v13-api", "API and Web Service", "OWASP ASVS 5.0 V13", "backend-api", 0.9, "ASVS V13", "API authentication, authorization, rate limiting, input validation, and response filtering.", "high", "static+dynamic")
d("asvs-v14-config", "Configuration", "OWASP ASVS 5.0 V14", "infra", 0.85, "ASVS V14", "Secure configuration management, dependency management, and removal of unnecessary features.", "high", "static")
d("asvs-v15-mobile", "Mobile Application Security", "OWASP ASVS 5.0 V15", "mobile-native", 0.85, "ASVS V15", "Mobile app binary protection, session handling, cryptographic storage, and platform-specific security.", "high", "static")
d("asvs-v16-iot", "IoT Application Security", "OWASP ASVS 5.0 V16", "iot-device", 0.8, "ASVS V16", "IoT device authentication, secure boot, firmware updates, and hardware security.", "high", "static+manual-review")

# ── OWASP API Security Top 10 2023 ───────────────────────────────────────────
d("owasp-api-bfla", "Broken Function Level Authorization", "OWASP API Security 2023 API1", "backend-api", 0.9, "API Top 10 API1", "Attackers can exploit API endpoints by modifying the request to access unauthorized functions.", "critical", "static+dynamic")
d("owasp-api-bOLA", "Broken Object Level Authorization", "OWASP API Security 2023 API2", "backend-api", 0.95, "API Top 10 API2", "Attackers can manipulate object IDs to access unauthorized data by modifying API requests.", "critical", "static+dynamic")
d("owasp-api-broken-auth", "Broken Authentication", "OWASP API Security 2023 API3", "backend-api", 0.9, "API Top 10 API3", "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise credentials or tokens.", "high", "static+dynamic")
d("owasp-api-unrestricted-resource", "Unrestricted Resource Consumption", "OWASP API Security 2023 API4", "backend-api", 0.85, "API Top 10 API4", "Lack of rate limiting, resource size limits, or request throttling allows denial of service.", "high", "dynamic")
d("owasp-api-broken-function-auth", "Broken Function Level Authorization", "OWASP API Security 2023 API5", "backend-api", 0.85, "API Top 10 API5", "Administrative functions accessible to regular users due to missing function-level authorization checks.", "high", "static+dynamic")
d("owasp-api-unrestricted-access", "Unrestricted Access to Sensitive Business Flows", "OWASP API Security 2023 API6", "backend-api", 0.8, "API Top 10 API6", "Attackers can abuse business flows (e.g., purchasing, referral) by automating API requests.", "medium", "dynamic")
d("owasp-api-srf", "Server-Side Request Forgery", "OWASP API Security 2023 API7", "backend-api", 0.85, "API Top 10 API7", "API endpoints fetch remote resources based on user-supplied URLs without validation.", "high", "static+dynamic")
d("owasp-api-security-misconfig", "Security Misconfiguration", "OWASP API Security 2023 API8", "infra", 0.85, "API Top 10 API8", "Missing security headers, permissive CORS, unnecessary HTTP methods, and verbose error messages.", "high", "static")
d("owasp-api-improper-inventory", "Improper Inventory Management", "OWASP API Security 2023 API9", "infra", 0.8, "API Top 10 API9", "Old or undocumented API versions exposed without proper access controls or deprecation.", "medium", "static")
d("owasp-api-consumption", "Unsafe Consumption of APIs", "OWASP API Security 2023 API10", "backend-api", 0.8, "API Top 10 API10", "Calling third-party APIs over untrusted channels without validating responses.", "medium", "static")

# ── OWASP Mobile Top 10 2024 ─────────────────────────────────────────────────
d("owasp-mobile-improper-platform", "Improper Platform Usage", "OWASP Mobile 2024 M1", "mobile-native", 0.85, "Mobile M1", "Misuse of platform security features like TouchID, Keychain, or Android permissions.", "high", "static")
d("owasp-mobile-insecure-data", "Insecure Data Storage", "OWASP Mobile 2024 M2", "mobile-native", 0.9, "Mobile M2", "Sensitive data stored insecurely on device (plaintext, world-readable, backup risks).", "critical", "static")
d("owasp-mobile-insecure-transport", "Insecure Communication", "OWASP Mobile 2024 M3", "mobile-native", 0.9, "Mobile M3", "Data transmitted without TLS, certificate pinning not implemented, or MITM vulnerabilities.", "critical", "static")
d("owasp-mobile-insecure-auth", "Insecure Authentication", "OWASP Mobile 2024 M4", "mobile-native", 0.85, "Mobile M4", "Weak authentication mechanisms, hardcoded credentials, or improper session management.", "high", "static+dynamic")
d("owasp-mobile-insufficient-crypto", "Insufficient Cryptography", "OWASP Mobile 2024 M5", "mobile-native", 0.85, "Mobile M5", "Use of weak or deprecated algorithms, hardcoded keys, or improper key storage.", "high", "static")
d("owasp-mobile-insecure-authorization", "Insecure Authorization", "OWASP Mobile 2024 M6", "mobile-native", 0.85, "Mobile M6", "Client-side authorization checks that can be bypassed, or missing server-side enforcement.", "high", "static+dynamic")
d("owasp-mobile-client-code-quality", "Client Code Quality", "OWASP Mobile 2024 M7", "mobile-native", 0.75, "Mobile M7", "Code quality issues leading to security vulnerabilities (buffer overflows, format strings, etc.).", "medium", "static")
d("owasp-mobile-code-tampering", "Code Tampering", "OWASP Mobile 2024 M8", "mobile-native", 0.8, "Mobile M8", "Application binary modified to alter behavior, bypass security controls, or extract data.", "medium", "static")
d("owasp-mobile-reverse-engineering", "Reverse Engineering", "OWASP Mobile 2024 M9", "mobile-native", 0.75, "Mobile M9", "Application can be reverse-engineered to extract secrets, algorithms, or business logic.", "medium", "static")
d("owasp-mobile-extraneous-functionality", "Extraneous Functionality", "OWASP Mobile 2024 M10", "mobile-native", 0.7, "Mobile M10", "Debug flags, test endpoints, or hidden functionality left in production builds.", "medium", "static")

# ── OWASP IoT Top 10 2024 ────────────────────────────────────────────────────
d("owasp-iot-weakened-identity", "Weakened Identification and Authentication", "OWASP IoT 2024 IoT1", "iot-device", 0.9, "IoT1", "Default credentials, hardcoded passwords, and weak authentication mechanisms on IoT devices.", "critical", "static")
d("owasp-iot-insecure-network", "Insecure Network Services", "OWASP IoT 2024 IoT2", "iot-device", 0.85, "IoT2", "Unnecessary open ports, unencrypted protocols, and missing network segmentation.", "high", "static+dynamic")
d("owasp-iot-insecure-ecosystem", "Insecure Ecosystem Interfaces", "OWASP IoT 2024 IoT3", "iot-device", 0.85, "IoT3", "Web, mobile, and cloud APIs lacking authentication, authorization, or input validation.", "high", "static+dynamic")
d("owasp-iot-insecure-data", "Insecure Data Storage and Retrieval", "OWASP IoT 2024 IoT4", "iot-device", 0.8, "IoT4", "Sensitive data stored in plaintext on devices, cloud, or mobile apps without encryption.", "high", "static")
d("owasp-iot-insecure-update", "Insecure Software/Firmware Updates", "OWASP IoT 2024 IoT5", "iot-device", 0.85, "IoT5", "Unsigned firmware, insecure update channels, or lack of rollback mechanisms.", "high", "static")
d("owasp-iot-insecure-data-transfer", "Insecure Data Transfer", "OWASP IoT 2024 IoT6", "iot-device", 0.85, "IoT6", "Data transmitted between device, cloud, and mobile app without encryption or integrity checks.", "high", "static")
d("owasp-iot-insecure-defaults", "Insecure Default Settings", "OWASP IoT 2024 IoT7", "iot-device", 0.8, "IoT7", "Devices shipped with debug interfaces enabled, unnecessary ports open, or default credentials.", "high", "static")
d("owasp-iot-lack-of-hardening", "Lack of Physical Hardening", "OWASP IoT 2024 IoT8", "iot-device", 0.75, "IoT8", "Exposed debug ports, JTAG interfaces, or lack of tamper detection on physical hardware.", "medium", "manual-review")
d("owasp-iot-insecure-privacy", "Lack of Privacy Protection", "OWASP IoT 2024 IoT9", "iot-device", 0.8, "IoT9", "Unnecessary collection of personal data, improper consent mechanisms, or data sold to third parties.", "high", "manual-review")
d("owasp-iot-insufficient-testing", "Insufficient Security Testing", "OWASP IoT 2024 IoT10", "iot-device", 0.75, "IoT10", "Lack of penetration testing, fuzzing, or security reviews during IoT product development.", "medium", "manual-review")

# ── OWASP LLM Top 10 2025 ────────────────────────────────────────────────────
d("owasp-llm-prompt-injection", "Prompt Injection", "OWASP LLM 2025 LLM01", "ai-ml", 0.95, "LLM01", "User inputs manipulate LLM behavior to bypass safety controls, extract secrets, or alter outputs.", "critical", "dynamic")
d("owasp-llm-sensitive-info", "Sensitive Information Disclosure", "OWASP LLM 2025 LLM02", "ai-ml", 0.9, "LLM02", "LLM reveals training data, system prompts, PII, or confidential information in responses.", "critical", "dynamic")
d("owasp-llm-supply-chain", "Supply Chain Vulnerabilities", "OWASP LLM 2025 LLM03", "ai-ml", 0.85, "LLM03", "Vulnerable pre-trained models, poisoned training data, or compromised ML libraries.", "high", "static")
d("owasp-llm-data-poisoning", "Data and Model Poisoning", "OWASP LLM 2025 LLM04", "ai-ml", 0.9, "LLM04", "Training data manipulated to introduce backdoors, biases, or vulnerabilities into the model.", "high", "static+manual-review")
d("owasp-llm-improper-output", "Improper Output Handling", "OWASP LLM 2025 LLM05", "ai-ml", 0.85, "LLM05", "LLM output used without sanitization leads to XSS, SSRF, or command injection downstream.", "high", "static")
d("owasp-llm-excessive-agency", "Excessive Agency", "OWASP LLM 2025 LLM06", "ai-ml", 0.85, "LLM06", "LLM has too many permissions or can perform unauthorized actions (tool use, API calls, file access).", "high", "static+dynamic")
d("owasp-llm-system-prompt-leak", "System Prompt Leakage", "OWASP LLM 2025 LLM07", "ai-ml", 0.8, "LLM07", "Attackers extract system prompts to understand app behavior and craft targeted attacks.", "high", "dynamic")
d("owasp-llm-vector-weakness", "Vector and Embedding Weaknesses", "OWASP LLM 2025 LLM08", "ai-ml", 0.8, "LLM08", "RAG pipeline vulnerabilities: poisoned vector stores, prompt injection via retrieved docs, weak access controls.", "high", "static+dynamic")
d("owasp-llm-misinformation", "Misinformation", "OWASP LLM 2025 LLM09", "ai-ml", 0.75, "LLM09", "LLM generates factually incorrect information presented as authoritative, leading to downstream harm.", "medium", "dynamic")
d("owasp-llm-unbounded-consumption", "Unbounded Consumption", "OWASP LLM 2025 LLM10", "ai-ml", 0.8, "LLM10", "Lack of rate limits or resource controls allows denial-of-wallet or resource exhaustion attacks.", "high", "dynamic")

# ── OWASP Top 10 for Node.js ─────────────────────────────────────────────────
d("owasp-nodejs-dependencies", "Vulnerable Dependencies", "OWASP Node.js Top 10", "backend-api", 0.85, "OWASP Node.js", "Using npm packages with known vulnerabilities or supply chain attacks.", "high", "static")
d("owasp-nodejs-auth", "Broken Authentication", "OWASP Node.js Top 10", "backend-api", 0.9, "OWASP Node.js", "Weak session management, credential stuffing, and improper password handling in Express/Node apps.", "high", "static+dynamic")
d("owasp-nodejs-xss", "Cross-Site Scripting (XSS)", "OWASP Node.js Top 10", "frontend-web", 0.85, "OWASP Node.js", "Reflected, stored, or DOM-based XSS in EJS, Pug, Handlebars, or React templates.", "high", "static")
d("owasp-nodejs-injection", "Injection", "OWASP Node.js Top 10", "backend-api", 0.9, "OWASP Node.js", "NoSQL injection, command injection, and template injection in Node.js applications.", "critical", "static+dynamic")
d("owasp-nodejs-prototype-pollution", "Prototype Pollution", "OWASP Node.js Top 10", "backend-api", 0.85, "OWASP Node.js", "Modifying Object.prototype to inject properties, leading to RCE or XSS.", "high", "static")
d("owasp-nodejs-open-redirect", "Open Redirect", "OWASP Node.js Top 10", "backend-api", 0.7, "OWASP Node.js", "Unvalidated redirect URLs allowing phishing or OAuth token theft.", "medium", "static+dynamic")
d("owasp-nodejs-insecure-deserialization", "Insecure Deserialization", "OWASP Node.js Top 10", "backend-api", 0.85, "OWASP Node.js", "Unsafe use of eval(), Function(), or JSON.parse on untrusted data.", "high", "static")
d("owasp-nodejs-missing-rate-limit", "Missing Rate Limiting", "OWASP Node.js Top 10", "backend-api", 0.8, "OWASP Node.js", "No rate limiting on login, API endpoints, or resource-intensive operations.", "high", "dynamic")
d("owasp-nodejs-security-misconfiguration", "Security Misconfiguration", "OWASP Node.js Top 10", "infra", 0.8, "OWASP Node.js", "Verbose error messages, unnecessary features enabled, and default configurations.", "medium", "static")
d("owasp-nodejs-insufficient-logging", "Insufficient Logging", "OWASP Node.js Top 10", "backend-api", 0.7, "OWASP Node.js", "Missing audit logs, no security event monitoring, and verbose debug output in production.", "medium", "static")

# ── OWASP Top 10 for PHP ─────────────────────────────────────────────────────
d("owasp-php-injection", "Injection", "OWASP PHP Top 10", "backend-api", 0.9, "OWASP PHP", "SQL injection, OS command injection, and LDAP injection in PHP applications.", "critical", "static+dynamic")
d("owasp-php-xss", "Cross-Site Scripting", "OWASP PHP Top 10", "frontend-web", 0.85, "OWASP PHP", "Reflected, stored, or DOM-based XSS due to missing output encoding.", "high", "static")
d("owasp-php-auth", "Broken Authentication", "OWASP PHP Top 10", "backend-api", 0.9, "OWASP PHP", "Weak password hashing, session fixation, and missing MFA in PHP apps.", "high", "static+dynamic")
d("owasp-php-access-control", "Broken Access Control", "OWASP PHP Top 10", "backend-api", 0.9, "OWASP PHP", "Missing authorization checks, IDOR, and privilege escalation.", "critical", "static+dynamic")
d("owasp-php-crypto", "Cryptographic Failures", "OWASP PHP Top 10", "backend-api", 0.85, "OWASP PHP", "Weak algorithms (MD5, SHA1), hardcoded keys, and insecure random number generation.", "high", "static")
d("owasp-php-config", "Security Misconfiguration", "OWASP PHP Top 10", "infra", 0.8, "OWASP PHP", "display_errors on, expose_php on, allow_url_include, and dangerous PHP settings.", "high", "static")
d("owasp-php-file-upload", "Insecure File Upload", "OWASP PHP Top 10", "backend-api", 0.85, "OWASP PHP", "Unrestricted file uploads allowing webshell execution or path traversal.", "critical", "static+dynamic")
d("owasp-php-deserialization", "Insecure Deserialization", "OWASP PHP Top 10", "backend-api", 0.85, "OWASP PHP", "Unsafe unserialize() calls leading to object injection and RCE.", "critical", "static")
d("owasp-php-sqli", "SQL Injection", "OWASP PHP Top 10", "backend-api", 0.95, "OWASP PHP", "Direct variable interpolation in SQL queries without prepared statements.", "critical", "static+dynamic")
d("owasp-php-rce", "Remote Code Execution", "OWASP PHP Top 10", "backend-api", 0.95, "OWASP PHP", "eval(), system(), exec(), passthru() on user-controlled input.", "critical", "static+dynamic")

# ── CWE Top 25 2024 ──────────────────────────────────────────────────────────
d("cwe-787-out-of-bounds", "Out-of-bounds Write", "CWE Top 25 2024 CWE-787", "native-code", 0.9, "CWE-787", "Writing data past the end or before the beginning of the intended buffer.", "critical", "static")
d("cwe-79-xss", "Improper Neutralization of Input During Web Page Generation (XSS)", "CWE Top 25 2024 CWE-79", "frontend-web", 0.9, "CWE-79", "User-controlled input included in web output without proper encoding.", "high", "static+dynamic")
d("cwe-89-sqli", "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", "CWE Top 25 2024 CWE-89", "backend-api", 0.95, "CWE-89", "User input inserted into SQL queries without parameterization.", "critical", "static+dynamic")
d("cwe-416-use-after-free", "Use After Free", "CWE Top 25 2024 CWE-416", "native-code", 0.9, "CWE-416", "Referencing memory after it has been freed, leading to crashes or code execution.", "critical", "static")
d("cwe-78-os-injection", "Improper Neutralization of Special Elements used in an OS Command", "CWE Top 25 2024 CWE-78", "backend-api", 0.9, "CWE-78", "User input passed to OS command execution functions without sanitization.", "critical", "static+dynamic")
d("cwe-20-input-validation", "Improper Input Validation", "CWE Top 25 2024 CWE-20", "backend-api", 0.85, "CWE-20", "Product does not validate or incorrectly validates input that can affect control flow.", "high", "static")
d("cwe-125-out-of-bounds-read", "Out-of-bounds Read", "CWE Top 25 2024 CWE-125", "native-code", 0.85, "CWE-125", "Reading data past the end of the intended buffer.", "high", "static")
d("cwe-22-path-traversal", "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", "CWE Top 25 2024 CWE-22", "backend-api", 0.9, "CWE-22", "External input used to construct pathname that references a file outside restricted directory.", "critical", "static+dynamic")
d("cwe-352-csrf", "Cross-Site Request Forgery", "CWE Top 25 2024 CWE-352", "frontend-web", 0.8, "CWE-352", "Web application does not sufficiently verify requests originated from trusted origin.", "high", "static+dynamic")
d("cwe-434-unrestricted-upload", "Unrestricted Upload of File with Dangerous Type", "CWE Top 25 2024 CWE-434", "backend-api", 0.85, "CWE-434", "Application allows file upload without restricting type, leading to code execution.", "critical", "static+dynamic")
d("cwe-862-authorization", "Missing Authorization", "CWE Top 25 2024 CWE-862", "backend-api", 0.9, "CWE-862", "Application does not perform authorization check when accessing resources.", "critical", "static+dynamic")
d("cwe-863-incorrect-auth", "Incorrect Authorization", "CWE Top 25 2024 CWE-863", "backend-api", 0.9, "CWE-863", "Authorization check is performed but is incorrect, allowing unintended access.", "critical", "static+dynamic")
d("cwe-798-hardcoded-credentials", "Use of Hard-coded Credentials", "CWE Top 25 2024 CWE-798", "backend-api", 0.9, "CWE-798", "Hard-coded password, cryptographic key, or other credentials in source code.", "critical", "static")
d("cwe-306-missing-auth", "Missing Authentication for Critical Function", "CWE Top 25 2024 CWE-306", "backend-api", 0.9, "CWE-306", "Critical function does not require authentication before allowing access.", "critical", "static+dynamic")
d("cwe-190-overflow", "Integer Overflow or Wraparound", "CWE Top 25 2024 CWE-190", "native-code", 0.85, "CWE-190", "Arithmetic operations produce a value that exceeds the range that can be represented.", "high", "static")
d("cwe-502-deserialization", "Deserialization of Untrusted Data", "CWE Top 25 2024 CWE-502", "backend-api", 0.9, "CWE-502", "Deserializing untrusted data without adequate verification, leading to RCE.", "critical", "static")
d("cwe-287-improper-auth", "Improper Authentication", "CWE Top 25 2024 CWE-287", "backend-api", 0.9, "CWE-287", "When an actor claims identity, the application does not verify the claim.", "critical", "static+dynamic")
d("cwe-476-null-pointer", "NULL Pointer Dereference", "CWE Top 25 2024 CWE-476", "native-code", 0.8, "CWE-476", "Dereferencing a NULL pointer leads to application crash or unexpected behavior.", "high", "static")
d("cwe-732-incorrect-permission", "Incorrect Permission Assignment for Critical Resource", "CWE Top 25 2024 CWE-732", "infra", 0.85, "CWE-732", "Resource has incorrect permissions, allowing unintended access.", "high", "static")
d("cwe-94-code-injection", "Improper Control of Generation of Code (Code Injection)", "CWE Top 25 2024 CWE-94", "backend-api", 0.95, "CWE-94", "Application constructs code from untrusted input without proper validation.", "critical", "static+dynamic")
d("cwe-611-improper-xml", "Improper Restriction of XML External Entity Reference", "CWE Top 25 2024 CWE-611", "backend-api", 0.85, "CWE-611", "XML parser processes external entities, leading to SSRF or file disclosure.", "high", "static")
d("cwe-918-ssrf", "Server-Side Request Forgery (SSRF)", "CWE Top 25 2024 CWE-918", "backend-api", 0.9, "CWE-918", "Web application fetches a remote resource without validating the user-supplied URL.", "high", "static+dynamic")
d("cwe-77-improper-neutralization", "Improper Neutralization of Special Elements used in a Command (Command Injection)", "CWE Top 25 2024 CWE-77", "backend-api", 0.95, "CWE-77", "User input included in command without proper escaping or validation.", "critical", "static+dynamic")
d("cwe-119-buffer-overflow", "Improper Restriction of Operations within the Bounds of a Memory Buffer", "CWE Top 25 2024 CWE-119", "native-code", 0.85, "CWE-119", "Operations read or write outside the intended buffer boundaries.", "critical", "static")
d("cwe-269-improper-privilege", "Improper Privilege Management", "CWE Top 25 2024 CWE-269", "backend-api", 0.85, "CWE-269", "Incorrect assignment or modification of privileges allows unauthorized access.", "high", "static+dynamic")

# ── CWE Extended (60 more) ────────────────────────────────────────────────────
d("cwe-200-information-exposure", "Exposure of Sensitive Information", "CWE-200", "backend-api", 0.8, "CWE-200", "Application exposes sensitive information to unauthorized actors.", "high", "static")
d("cwe-209-information-through-error", "Generation of Error Message Containing Sensitive Information", "CWE-209", "backend-api", 0.7, "CWE-209", "Error messages reveal sensitive system information to users.", "medium", "static")
d("cwe-284-improper-access-control", "Improper Access Control", "CWE-284", "backend-api", 0.9, "CWE-284", "Application does not properly restrict access to resources.", "critical", "static+dynamic")
d("cwe-310-cryptographic-issues", "Cryptographic Issues", "CWE-310", "backend-api", 0.85, "CWE-310", "Weaknesses in cryptographic implementations or key management.", "high", "static")
d("cwe-311-missing-encryption", "Missing Encryption of Sensitive Data", "CWE-311", "backend-api", 0.9, "CWE-311", "Sensitive data is not encrypted before storage or transmission.", "critical", "static")
d("cwe-319-cleartext-transmission", "Cleartext Transmission of Sensitive Information", "CWE-319", "backend-api", 0.9, "CWE-319", "Sensitive data transmitted in cleartext over a network.", "critical", "static")
d("cwe-327-broken-crypto", "Use of a Broken or Risky Cryptographic Algorithm", "CWE-327", "backend-api", 0.85, "CWE-327", "Use of known weak cryptographic algorithms.", "high", "static")
d("cwe-330-use-of-insufficient-random", "Use of Insufficiently Random Values", "CWE-330", "backend-api", 0.85, "CWE-330", "Use of random values for security-critical operations with insufficient entropy.", "high", "static")
d("cwe-338-cryptographic-prng", "Use of Cryptographically Weak PRNG", "CWE-338", "backend-api", 0.85, "CWE-338", "Cryptographic operations use non-cryptographic random number generators.", "high", "static")
d("cwe-347-verification-bypass", "Improper Verification of Cryptographic Signature", "CWE-347", "backend-api", 0.9, "CWE-347", "Application does not verify the cryptographic signature of data.", "critical", "static")
d("cwe-353-missing-integrity", "Missing Support for Integrity Check", "CWE-353", "backend-api", 0.8, "CWE-353", "Application does not use integrity checks to detect data modification.", "high", "static")
d("cwe-362-race-condition", "Concurrent Execution Using Shared Resource with Improper Synchronization", "CWE-362", "backend-api", 0.8, "CWE-362", "Race condition allows unintended behavior when concurrent processes share resources.", "high", "static")
d("cwe-367-time-of-check-time-of-use", "Time-of-check Time-of-use (TOCTOU) Race Condition", "CWE-367", "backend-api", 0.8, "CWE-367", "TOCTOU race condition between checking a condition and using the resource.", "high", "static")
d("cwe-377-insecure-temp-file", "Insecure Temporary File Creation", "CWE-377", "backend-api", 0.7, "CWE-377", "Creation of temporary files with insecure permissions or predictable names.", "medium", "static")
d("cwe-378-creation-temp-file-with-privileged", "Creation of Temporary File With Insecure Permissions", "CWE-378", "backend-api", 0.7, "CWE-378", "Temporary files created with overly permissive file system permissions.", "medium", "static")
d("cwe-384-session-fixation", "Session Fixation", "CWE-384", "backend-api", 0.85, "CWE-384", "Application does not regenerate session identifiers after authentication.", "high", "static+dynamic")
d("cwe-390-error-detection", "Detection of Error Condition Without Action", "CWE-390", "backend-api", 0.7, "CWE-390", "Application detects errors but does not take appropriate corrective action.", "medium", "static")
d("cwe-400-uncontrolled-resource", "Uncontrolled Resource Consumption", "CWE-400", "backend-api", 0.8, "CWE-400", "Application does not properly control the consumption of resources.", "high", "dynamic")
d("cwe-401-missing-release-of-memory", "Missing Release of Memory after Effective Lifetime", "CWE-401", "native-code", 0.75, "CWE-401", "Memory is allocated but not released, leading to resource exhaustion.", "medium", "static")
d("cwe-404-improper-resource-shutdown", "Improper Resource Shutdown or Release", "CWE-404", "backend-api", 0.7, "CWE-404", "Application does not properly release resources, leading to resource exhaustion.", "medium", "static")
d("cwe-425-direct-request-forbidden", "Direct Request ('Forced Browsing')", "CWE-425", "backend-api", 0.8, "CWE-425", "Application does not adequately enforce appropriate authorization on restricted URLs.", "high", "dynamic")
d("cwe-434-unrestricted-file", "Unrestricted Upload of File with Dangerous Type", "CWE-434", "backend-api", 0.85, "CWE-434", "Application allows upload of executable files that can be run on the server.", "critical", "static+dynamic")
d("cwe-444-integration-multiple-representations", "Interpretation Conflict", "CWE-444", "backend-api", 0.75, "CWE-444", "HTTP request/response interpreted differently by different systems or components.", "medium", "static")
d("cwe-451-visual-misrepresentation", "User Interface (UI) Misrepresentation of Critical Information", "CWE-451", "frontend-web", 0.75, "CWE-451", "UI displays incorrect or misleading information about security-critical data.", "medium", "manual-review")
d("cwe-456-missing-initialization", "Missing Initialization", "CWE-456", "backend-api", 0.7, "CWE-456", "Critical variable, resource, or structure is not initialized before use.", "medium", "static")
d("cwe-460-improper-cleanup", "Improper Cleanup on Thrown Exception", "CWE-460", "backend-api", 0.7, "CWE-460", "Resources not properly cleaned up when an exception is thrown.", "medium", "static")
d("cwe-472-external-control", "External Control of Assumed-Immutable Web Parameter", "CWE-472", "frontend-web", 0.8, "CWE-472", "Web application assumes parameters are immutable but attackers can modify them.", "high", "static+dynamic")
d("cwe-497-exposure-system-info", "Exposure of Sensitive System Information to an Unauthorized Control Sphere", "CWE-497", "backend-api", 0.85, "CWE-497", "Application exposes internal system information (stack traces, configs, paths) to users.", "high", "static")
d("cwe-501-trust-boundary-violation", "Trust Boundary Violation", "CWE-501", "backend-api", 0.8, "CWE-501", "Application violates trust boundaries by importing data from untrusted sources without validation.", "high", "static")
d("cwe-521-password-policy", "Weak Password Requirements", "CWE-521", "backend-api", 0.8, "CWE-521", "Password policy does not enforce sufficient complexity, length, or rotation requirements.", "high", "static")
d("cwe-522-insufficiently-protected", "Insufficiently Protected Credentials", "CWE-522", "backend-api", 0.9, "CWE-522", "Credentials transmitted or stored without adequate protection.", "critical", "static")
d("cwe-532-insertion-sensitive-info", "Insertion of Sensitive Information into Log File", "CWE-532", "backend-api", 0.75, "CWE-532", "Application writes sensitive information (passwords, tokens, PII) to log files.", "high", "static")
d("cwe-541-inclusion-sensitive-info", "Inclusion of Sensitive Information in Include Files", "CWE-541", "backend-api", 0.8, "CWE-541", "Sensitive data included in include/header files that may be exposed.", "high", "static")
d("cwe-548-exposure-information", "Exposure of Information Through Directory Listing", "CWE-548", "infra", 0.75, "CWE-548", "Web server directory listing enabled, exposing file structure and sensitive files.", "medium", "static")
d("cwe-550-server-generated-error", "Exposure of Sensitive Information Through Server Error Messages", "CWE-550", "infra", 0.8, "CWE-550", "Server error messages contain sensitive system information visible to users.", "high", "static")
d("cwe-561-no-automation", "Use of Homoglyphs in URL Path", "CWE-561", "frontend-web", 0.7, "CWE-561", "Application does not normalize or validate URL paths for homoglyph attacks.", "medium", "static")
d("cwe-601-open-redirect", "URL Redirection to Untrusted Site ('Open Redirect')", "CWE-601", "backend-api", 0.75, "CWE-601", "Application accepts unvalidated URL redirections that could send users to malicious sites.", "medium", "static+dynamic")
d("cwe-610-exposure-redirect", "Reliance on Obfuscation or Obscurity as a Security Mechanism", "CWE-610", "backend-api", 0.7, "CWE-610", "Application relies on secrecy or obscurity rather than proper access controls.", "medium", "manual-review")
d("cwe-643-improper-neutralization-xpath", "Improper Neutralization of Data within XPath Expressions", "CWE-643", "backend-api", 0.8, "CWE-643", "User input is included in XPath queries without proper escaping.", "high", "static")
d("cwe-650-trust-HTTP-methods", "HTTP Verb Tampering", "CWE-650", "backend-api", 0.7, "CWE-650", "Application does not properly restrict access based on HTTP method.", "medium", "static+dynamic")
d("cwe-652-improper-neutralization-data-within-code-generation", "Improper Neutralization of Data within Code Generation Macros", "CWE-652", "backend-api", 0.85, "CWE-652", "User input included in code generation templates or macros without sanitization.", "high", "static")
d("cwe-668-exposure-resource", "Exposure of Resource to Wrong Sphere", "CWE-668", "backend-api", 0.85, "CWE-668", "Application exposes a resource to the wrong control sphere.", "high", "static+dynamic")
d("cwe-674-uncontrolled-recursion", "Uncontrolled Recursion", "CWE-674", "backend-api", 0.75, "CWE-674", "Application does not limit recursion depth, potentially leading to stack overflow.", "medium", "static")
d("cwe-693-protection-mechanism", "Protection Mechanism Failure", "CWE-693", "backend-api", 0.85, "CWE-693", "Application does not correctly use its protection mechanisms.", "high", "static")
d("cwe-704-incorrect-type-conversion", "Incorrect Type Conversion or Cast", "CWE-704", "backend-api", 0.8, "CWE-704", "Application performs unsafe type conversions that could lead to buffer overflows or logic errors.", "high", "static")
d("cwe-733-compilation-code-injection", "Compiler Optimization Removal or Modification of Security-critical Code", "CWE-733", "native-code", 0.8, "CWE-733", "Compiler optimizations remove or modify security-critical code.", "high", "static")
d("cwe-770-allocation-without-limits", "Allocation of Resources Without Limits or Throttling", "CWE-770", "backend-api", 0.85, "CWE-770", "Application allocates resources without imposing size or number limits.", "high", "dynamic")
d("cwe-775-missing-release-descriptor", "Missing Release of File Descriptor or Handle after Effective Lifetime", "CWE-775", "backend-api", 0.7, "CWE-775", "File descriptors not properly closed, leading to resource exhaustion.", "medium", "static")
d("cwe-799-improper-control-identifier", "Improper Control of Interaction Frequency", "CWE-799", "backend-api", 0.8, "CWE-799", "Application does not restrict the rate or number of interactions.", "high", "dynamic")
d("cwe-807-improper-neutralization-user", "Improper Neutralization of Input During Web Page Generation", "CWE-807", "frontend-web", 0.85, "CWE-807", "User-controlled input is reflected in web pages without encoding.", "high", "static+dynamic")
d("cwe-829-inclusion-functionality", "Inclusion of Functionality from Untrusted Control Sphere", "CWE-829", "backend-api", 0.85, "CWE-829", "Application includes functionality from untrusted sources without validation.", "high", "static")
d("cwe-833-deadlock", "Deadlock", "CWE-833", "backend-api", 0.75, "CWE-833", "Application contains code that can deadlock when concurrent operations are used.", "medium", "static")
d("cwe-838-improper-encoding", "Use of Encoding for Authentication or Authorization", "CWE-838", "backend-api", 0.8, "CWE-838", "Application uses encoding in place of proper authentication or authorization.", "high", "static")
d("cwe-915-improper-neutralization-mass-assignment", "Improperly Controlled Modification of Dynamically-Determined Object Attributes (Mass Assignment)", "CWE-915", "backend-api", 0.85, "CWE-915", "Application automatically assigns object attributes from user input without restriction.", "high", "static")
d("cwe-939-improper-authorization-handler", "Improper Authorization in Handler for Custom URL Scheme", "CWE-939", "mobile-native", 0.8, "CWE-939", "Application does not properly authorize access to resources via custom URL schemes.", "high", "static+dynamic")

# ── NIST SP 800-53 Rev 5 (80 controls) ────────────────────────────────────────
# Access Control
d("nist-ac-1", "Access Control Policy and Procedures", "NIST SP 800-53 AC-1", "infra", 0.7, "AC-1", "Organization develops, documents, and disseminates access control policy.", "medium", "manual-review")
d("nist-ac-2", "Account Management", "NIST SP 800-53 AC-2", "infra", 0.85, "AC-2", "Organization manages information system accounts including establishing, activating, modifying, reviewing, disabling, and removing accounts.", "high", "static+manual-review")
d("nist-ac-3", "Access Enforcement", "NIST SP 800-53 AC-3", "backend-api", 0.9, "AC-3", "System enforces approved authorizations for logical access control.", "critical", "static+dynamic")
d("nist-ac-4", "Information Flow Enforcement", "NIST SP 800-53 AC-4", "backend-api", 0.85, "AC-4", "System enforces approved authorizations for controlling the flow of information.", "high", "static+dynamic")
d("nist-ac-5", "Separation of Duties", "NIST SP 800-53 AC-5", "infra", 0.75, "AC-5", "Organization separates duties of individuals to reduce risk of fraud or error.", "medium", "manual-review")
d("nist-ac-6", "Least Privilege", "NIST SP 800-53 AC-6", "infra", 0.9, "AC-6", "Organization employs the principle of least privilege for system accounts.", "critical", "static+dynamic")
d("nist-ac-7", "Unsuccessful Login Attempts", "NIST SP 800-53 AC-7", "backend-api", 0.8, "AC-7", "System limits consecutive failed login attempts.", "high", "static+dynamic")
d("nist-ac-8", "System Use Notification", "NIST SP 800-53 AC-8", "frontend-web", 0.65, "AC-8", "System displays a system use notification message before login.", "medium", "manual-review")
d("nist-ac-9", "Previous Logon Access Notification", "NIST SP 800-53 AC-9", "backend-api", 0.7, "AC-9", "System notifies users of previous successful logons.", "medium", "static")
d("nist-ac-10", "Concurrent Session Control", "NIST SP 800-53 AC-10", "backend-api", 0.8, "AC-10", "System limits the number of concurrent sessions per user.", "high", "static+dynamic")
d("nist-ac-11", "Session Lock", "NIST SP 800-53 AC-11", "backend-api", 0.75, "AC-11", "System prevents further access by initiating a session lock after inactivity.", "medium", "static+dynamic")
d("nist-ac-12", "Session Termination", "NIST SP 800-53 AC-12", "backend-api", 0.8, "AC-12", "System automatically terminates a session after defined conditions.", "high", "static+dynamic")
d("nist-ac-14", "Permitted Actions without Identification", "NIST SP 800-53 AC-14", "backend-api", 0.7, "AC-14", "System permits actions without identification under defined circumstances.", "medium", "manual-review")
d("nist-ac-17", "Remote Access", "NIST SP 800-53 AC-17", "infra", 0.85, "AC-17", "Organization establishes and manages remote access to the system.", "high", "static+dynamic")
d("nist-ac-18", "Wireless Access", "NIST SP 800-53 AC-18", "infra", 0.8, "AC-18", "Organization establishes and manages wireless access to the system.", "high", "static+dynamic")
d("nist-ac-19", "Access Control for Portable Devices", "NIST SP 800-53 AC-19", "infra", 0.75, "AC-19", "Organization manages access to portable devices containing organizational information.", "medium", "manual-review")
d("nist-ac-20", "Use of External Systems", "NIST SP 800-53 AC-20", "infra", 0.8, "AC-20", "Organization establishes terms for external system access.", "high", "manual-review")
d("nist-ac-21", "Information Sharing", "NIST SP 800-53 AC-21", "infra", 0.75, "AC-21", "Organization facilitates information sharing using appropriate mechanisms.", "medium", "manual-review")
d("nist-ac-22", "Publicly Accessible Content", "NIST SP 800-53 AC-22", "infra", 0.7, "AC-22", "Organization manages public access to system resources.", "medium", "static")

# Audit and Accountability
d("nist-au-1", "Audit and Accountability Policy", "NIST SP 800-53 AU-1", "infra", 0.7, "AU-1", "Organization develops and documents audit policy.", "medium", "manual-review")
d("nist-au-2", "Audit Events", "NIST SP 800-53 AU-2", "infra", 0.8, "AU-2", "Organization determines which events to log as part of the audit trail.", "high", "static")
d("nist-au-3", "Content of Audit Records", "NIST SP 800-53 AU-3", "infra", 0.8, "AU-3", "Audit records contain sufficient information to establish what happened, when, and by whom.", "high", "static")
d("nist-au-4", "Audit Storage Capacity", "NIST SP 800-53 AU-4", "infra", 0.7, "AU-4", "System allocates sufficient audit log storage capacity.", "medium", "manual-review")
d("nist-au-5", "Response to Audit Processing Failures", "NIST SP 800-53 AU-5", "infra", 0.75, "AU-5", "System alerts appropriate personnel when audit log storage capacity is reached.", "medium", "static")
d("nist-au-6", "Audit Review, Analysis, and Reporting", "NIST SP 800-53 AU-6", "infra", 0.8, "AU-6", "Organization reviews and analyzes audit records to identify unusual activity.", "high", "manual-review")
d("nist-au-8", "Time Stamps", "NIST SP 800-53 AU-8", "infra", 0.75, "AU-8", "System uses internal system clocks to generate time stamps for audit records.", "medium", "static")
d("nist-au-9", "Protection of Audit Information", "NIST SP 800-53 AU-9", "infra", 0.85, "AU-9", "System protects audit information from unauthorized modification and deletion.", "high", "static")
d("nist-au-10", "Non-repudiation", "NIST SP 800-53 AU-10", "backend-api", 0.85, "AU-10", "System provides non-repudiation of information system actions.", "high", "static+dynamic")
d("nist-au-11", "Audit Record Retention", "NIST SP 800-53 AU-11", "infra", 0.7, "AU-11", "Organization retains audit records for defined period.", "medium", "manual-review")
d("nist-au-12", "Audit Record Generation", "NIST SP 800-53 AU-12", "infra", 0.8, "AU-12", "System generates audit records for defined events.", "high", "static")

# Configuration Management
d("nist-cm-1", "Configuration Management Policy", "NIST SP 800-53 CM-1", "infra", 0.7, "CM-1", "Organization develops configuration management policy and procedures.", "medium", "manual-review")
d("nist-cm-2", "Baseline Configuration", "NIST SP 800-53 CM-2", "infra", 0.8, "CM-2", "Organization develops and maintains a current baseline configuration of the system.", "high", "static")
d("nist-cm-3", "Configuration Change Control", "NIST SP 800-53 CM-3", "infra", 0.8, "CM-3", "Organization tracks and controls changes to the system baseline configuration.", "high", "static+manual-review")
d("nist-cm-4", "Impact Analyses", "NIST SP 800-53 CM-4", "infra", 0.75, "CM-4", "Organization analyzes changes to the system to determine potential security impact.", "medium", "manual-review")
d("nist-cm-5", "Access Restrictions for Changes", "NIST SP 800-53 CM-5", "infra", 0.85, "CM-5", "Organization defines, documents, and implements access restrictions for changes to the system.", "high", "static")
d("nist-cm-6", "Configuration Settings", "NIST SP 800-53 CM-6", "infra", 0.85, "CM-6", "Organization configures system settings to the most restrictive security level.", "high", "static")
d("nist-cm-7", "Least Functionality", "NIST SP 800-53 CM-7", "infra", 0.85, "CM-7", "Organization restricts system functionality to only what is required.", "high", "static")
d("nist-cm-8", "System Component Inventory", "NIST SP 800-53 CM-8", "infra", 0.75, "CM-8", "Organization develops and maintains an inventory of system components.", "medium", "static+manual-review")
d("nist-cm-9", "Configuration Management Plan", "NIST SP 800-53 CM-9", "infra", 0.7, "CM-9", "Organization develops a configuration management plan for the system.", "medium", "manual-review")
d("nist-cm-10", "Software Usage Restrictions", "NIST SP 800-53 CM-10", "infra", 0.8, "CM-10", "Organization controls the use of software on organizational systems.", "high", "static")
d("nist-cm-11", "User-Installed Software", "NIST SP 800-53 CM-11", "infra", 0.8, "CM-11", "Organization restricts installation of software to authorized personnel.", "high", "static+dynamic")

# Identification and Authentication
d("nist-ia-1", "Identification and Authentication Policy", "NIST SP 800-53 IA-1", "infra", 0.7, "IA-1", "Organization develops identification and authentication policy.", "medium", "manual-review")
d("nist-ia-2", "Identification and Authentication (Organizational Users)", "NIST SP 800-53 IA-2", "backend-api", 0.9, "IA-2", "System uniquely identifies and authenticates organizational users.", "critical", "static+dynamic")
d("nist-ia-3", "Device Identification and Authentication", "NIST SP 800-53 IA-3", "backend-api", 0.8, "IA-3", "System uniquely identifies and authenticates devices.", "high", "static+dynamic")
d("nist-ia-4", "Identifier Management", "NIST SP 800-53 IA-4", "backend-api", 0.8, "IA-4", "Organization manages user identifiers including uniqueness, disabling, and reuse prevention.", "high", "static")
d("nist-ia-5", "Authenticator Management", "NIST SP 800-53 IA-5", "backend-api", 0.9, "IA-5", "Organization manages authenticators including password complexity, composition, and rotation.", "critical", "static+dynamic")
d("nist-ia-6", "Authentication Feedback", "NIST SP 800-53 IA-6", "frontend-web", 0.7, "IA-6", "System obscures authentication feedback (password masking) to prevent observation.", "medium", "static")
d("nist-ia-7", "Cryptographic Module Authentication", "NIST SP 800-53 IA-7", "backend-api", 0.85, "IA-7", "System uses and validates authentication mechanisms at the cryptographic module level.", "high", "static")
d("nist-ia-8", "Non-Organizational User Identification and Authentication", "NIST SP 800-53 IA-8", "backend-api", 0.8, "IA-8", "System uniquely identifies and authenticates non-organizational users.", "high", "static+dynamic")

# System and Communications Protection
d("nist-sc-1", "System and Communications Protection Policy", "NIST SP 800-53 SC-1", "infra", 0.7, "SC-1", "Organization develops system and communications protection policy.", "medium", "manual-review")
d("nist-sc-2", "Application Partitioning", "NIST SP 800-53 SC-2", "infra", 0.8, "SC-2", "System separates user functionality from system management functionality.", "high", "static")
d("nist-sc-3", "Security Function Isolation", "NIST SP 800-53 SC-3", "infra", 0.85, "SC-3", "System isolates security functions from non-security functions.", "high", "static")
d("nist-sc-4", "Information in Shared Resources", "NIST SP 800-53 SC-4", "infra", 0.8, "SC-4", "System prevents unauthorized and unintended information transfer through shared resources.", "high", "static")
d("nist-sc-5", "Denial of Service Protection", "NIST SP 800-53 SC-5", "infra", 0.85, "SC-5", "System limits the effects of denial of service attacks.", "high", "dynamic")
d("nist-sc-6", "Resource Availability", "NIST SP 800-53 SC-6", "infra", 0.8, "SC-6", "System allocates resources to prevent or mitigate denial of service.", "high", "static+dynamic")
d("nist-sc-7", "Boundary Protection", "NIST SP 800-53 SC-7", "infra", 0.85, "SC-7", "System monitors and controls communications at external boundaries.", "high", "static+dynamic")
d("nist-sc-8", "Transmission Confidentiality and Integrity", "NIST SP 800-53 SC-8", "infra", 0.9, "SC-8", "System protects transmission confidentiality and integrity using encryption.", "critical", "static")
d("nist-sc-9", "Transmission Confidentiality", "NIST SP 800-53 SC-9", "infra", 0.85, "SC-9", "System protects the confidentiality of transmitted information.", "high", "static")
d("nist-sc-10", "Network Disconnect", "NIST SP 800-53 SC-10", "infra", 0.75, "SC-10", "System terminates the network connection after defined period of inactivity.", "medium", "static+dynamic")
d("nist-sc-12", "Establishment and Management of Cryptographic Keys", "NIST SP 800-53 SC-12", "backend-api", 0.9, "SC-12", "System establishes and manages cryptographic keys for encryption.", "critical", "static")
d("nist-sc-13", "Cryptographic Protection", "NIST SP 800-53 SC-13", "backend-api", 0.9, "SC-13", "System implements FIPS-validated cryptographic modules.", "critical", "static")
d("nist-sc-15", "Collaborative Computing Devices", "NIST SP 800-53 SC-15", "infra", 0.75, "SC-15", "System prohibits remote activation of collaborative computing mechanisms.", "medium", "static")
d("nist-sc-17", "Certificate Management", "NIST SP 800-53 SC-17", "infra", 0.85, "SC-17", "System manages PKI certificates and trust anchors.", "high", "static")
d("nist-sc-18", "Mobile Code", "NIST SP 800-53 SC-18", "backend-api", 0.8, "SC-18", "System controls the use of mobile code (Java, JavaScript, ActiveX).", "high", "static")
d("nist-sc-20", "Secure Name Resolution", "NIST SP 800-53 SC-20", "infra", 0.85, "SC-20", "System prevents DNS spoofing and ensures secure name resolution.", "high", "static+dynamic")
d("nist-sc-21", "Secure Name Resolution Authoritative", "NIST SP 800-53 SC-21", "infra", 0.85, "SC-21", "System implements secure name resolution for authoritative data.", "high", "static")
d("nist-sc-23", "Operated System Security", "NIST SP 800-53 SC-23", "infra", 0.8, "SC-23", "System ensures authenticity of mobile device connections.", "high", "static")
d("nist-sc-24", "Fail in Known State", "NIST SP 800-53 SC-24", "backend-api", 0.8, "SC-24", "System fails in a known secure state when defined failure conditions occur.", "high", "static")
d("nist-sc-28", "Protection of Information at Rest", "NIST SP 800-53 SC-28", "backend-api", 0.9, "SC-28", "System protects information at rest using encryption.", "critical", "static")

# System and Information Integrity
d("nist-si-1", "System and Information Integrity Policy", "NIST SP 800-53 SI-1", "infra", 0.7, "SI-1", "Organization develops system and information integrity policy.", "medium", "manual-review")
d("nist-si-2", "Flaw Remediation", "NIST SP 800-53 SI-2", "infra", 0.85, "SI-2", "Organization identifies, reports, and corrects information system flaws.", "high", "static")
d("nist-si-3", "Malicious Code Protection", "NIST SP 800-53 SI-3", "infra", 0.85, "SI-3", "System implements malicious code protection mechanisms.", "high", "static+dynamic")
d("nist-si-4", "System Monitoring", "NIST SP 800-53 SI-4", "infra", 0.85, "SI-4", "Organization monitors the system for attacks and indicators of compromise.", "high", "static+dynamic")
d("nist-si-5", "Security Alerts and Advisories", "NIST SP 800-53 SI-5", "infra", 0.75, "SI-5", "Organization receives and responds to security alerts and advisories.", "medium", "manual-review")
d("nist-si-6", "Security and Privacy Function Verification", "NIST SP 800-53 SI-6", "infra", 0.8, "SI-6", "System verifies security and privacy functions are functioning correctly.", "high", "static")
d("nist-si-7", "Software Firmware and Information Integrity", "NIST SP 800-53 SI-7", "backend-api", 0.9, "SI-7", "System verifies integrity of software, firmware, and information.", "critical", "static")
d("nist-si-8", "Spam Protection", "NIST SP 800-53 SI-8", "infra", 0.7, "SI-8", "System implements spam protection mechanisms.", "medium", "dynamic")
d("nist-si-10", "Information Input Validation", "NIST SP 800-53 SI-10", "backend-api", 0.9, "SI-10", "System checks validity of information inputs.", "critical", "static")
d("nist-si-11", "Error Handling", "NIST SP 800-53 SI-11", "backend-api", 0.8, "SI-11", "System handles errors in a secure manner, preventing information leakage.", "high", "static")
d("nist-si-12", "Information Management and Retention", "NIST SP 800-53 SI-12", "backend-api", 0.7, "SI-12", "Organization manages system-generated information and retains it per policy.", "medium", "static")
d("nist-si-15", "Information Output Filtering", "NIST SP 800-53 SI-15", "backend-api", 0.8, "SI-15", "System filters information outputs to prevent information leakage.", "high", "static")

# ── NIST CSF 2.0 ─────────────────────────────────────────────────────────────
d("nist-csf-govern", "Govern Function", "NIST CSF 2.0", "infra", 0.8, "CSF 2.0 GV", "Organizational context, risk management strategy, and supply chain risk management.", "high", "manual-review")
d("nist-csf-identify", "Identify Function", "NIST CSF 2.0", "infra", 0.8, "CSF 2.0 ID", "Asset management, risk assessment, and improvement planning.", "high", "static+manual-review")
d("nist-csf-protect", "Protect Function", "NIST CSF 2.0", "infra", 0.9, "CSF 2.0 PR", "Identity management, access control, awareness training, data security, and platform security.", "critical", "static+dynamic")
d("nist-csf-detect", "Detect Function", "NIST CSF 2.0", "infra", 0.85, "CSF 2.0 DE", "Continuous monitoring, adverse event analysis, and anomaly detection.", "high", "static+dynamic")
d("nist-csf-respond", "Respond Function", "NIST CSF 2.0", "infra", 0.8, "CSF 2.0 RS", "Incident management, analysis, mitigation, and reporting.", "high", "manual-review")
d("nist-csf-recover", "Recover Function", "NIST CSF 2.0", "infra", 0.75, "CSF 2.0 RC", "Recovery planning, communications, and execution.", "medium", "manual-review")

# ── SANS Top 25 ───────────────────────────────────────────────────────────────
d("sans-buffer-overflow", "Buffer Overflow", "SANS Top 25", "native-code", 0.9, "SANS", "Writing beyond allocated memory boundaries.", "critical", "static")
d("sans-csrf", "Cross-Site Request Forgery", "SANS Top 25", "frontend-web", 0.8, "SANS", "Unauthorized commands transmitted from a trusted user.", "high", "static+dynamic")
d("sans-command-injection", "Command Injection", "SANS Top 25", "backend-api", 0.95, "SANS", "Untrusted data sent to an interpreter as part of a command.", "critical", "static+dynamic")
d("sans-crypto-failures", "Cryptographic Failures", "SANS Top 25", "backend-api", 0.85, "SANS", "Weak encryption algorithms, key management, or random number generation.", "high", "static")
d("sans-cross-site-scripting", "Cross-Site Scripting (XSS)", "SANS Top 25", "frontend-web", 0.9, "SANS", "Untrusted data included in web output without validation.", "high", "static+dynamic")
d("sans-dos", "Denial of Service", "SANS Top 25", "infra", 0.8, "SANS", "Resource exhaustion through flooding or algorithmic complexity attacks.", "high", "dynamic")
d("sans-error-handling", "Improper Error Handling", "SANS Top 25", "backend-api", 0.75, "SANS", "Verbose error messages exposing sensitive system information.", "medium", "static")
d("sans-file-inclusion", "File Inclusion", "SANS Top 25", "backend-api", 0.9, "SANS", "Local or remote file inclusion via unvalidated input.", "critical", "static+dynamic")
d("sans-hardcoded-credentials", "Hard-coded Credentials", "SANS Top 25", "backend-api", 0.9, "SANS", "Passwords, keys, or tokens embedded in source code.", "critical", "static")
d("sans-insecure-deserialization", "Insecure Deserialization", "SANS Top 25", "backend-api", 0.9, "SANS", "Untrusted data deserialized without validation, leading to RCE.", "critical", "static")
d("sans-information-leakage", "Information Leakage", "SANS Top 25", "backend-api", 0.8, "SANS", "Sensitive information exposed through error messages, logs, or headers.", "high", "static")
d("sans-injection", "Injection", "SANS Top 25", "backend-api", 0.95, "SANS", "SQL, LDAP, NoSQL, OS, and other injection attacks.", "critical", "static+dynamic")
d("sans-insufficient-auth", "Insufficient Authentication", "SANS Top 25", "backend-api", 0.9, "SANS", "Weak or missing authentication mechanisms.", "critical", "static+dynamic")
d("sans-insufficient-authorization", "Insufficient Authorization", "SANS Top 25", "backend-api", 0.9, "SANS", "Missing or incorrect authorization checks.", "critical", "static+dynamic")
d("sans-insufficient-session-management", "Insufficient Session Management", "SANS Top 25", "backend-api", 0.85, "SANS", "Weak session token generation, fixation, or expiry.", "high", "static+dynamic")
d("sans-misconfiguration", "Security Misconfiguration", "SANS Top 25", "infra", 0.85, "SANS", "Default settings, unnecessary features, or missing hardening.", "high", "static")
d("sans-open-redirect", "Open Redirect", "SANS Top 25", "backend-api", 0.7, "SANS", "Unvalidated URL redirects enabling phishing.", "medium", "static+dynamic")
d("sans-path-traversal", "Path Traversal", "SANS Top 25", "backend-api", 0.9, "SANS", "Access files outside intended directory via crafted paths.", "critical", "static+dynamic")
d("sans-race-condition", "Race Condition", "SANS Top 25", "backend-api", 0.8, "SANS", "Concurrent access vulnerabilities leading to privilege escalation.", "high", "static")
d("sans-sensitive-data-exposure", "Sensitive Data Exposure", "SANS Top 25", "backend-api", 0.9, "SANS", "Inadequate protection of sensitive data at rest or in transit.", "critical", "static")
d("sans-sql-injection", "SQL Injection", "SANS Top 25", "backend-api", 0.95, "SANS", "Malicious SQL statements inserted via user input.", "critical", "static+dynamic")
d("sans-ssrf", "Server-Side Request Forgery", "SANS Top 25", "backend-api", 0.85, "SANS", "Application fetches unvalidated user-supplied URLs.", "high", "static+dynamic")
d("sans-unvalidated-redirects", "Unvalidated Redirects and Forwards", "SANS Top 25", "backend-api", 0.75, "SANS", "Redirects to malicious sites via unvalidated URL parameters.", "medium", "static+dynamic")
d("sans-use-after-free", "Use After Free", "SANS Top 25", "native-code", 0.9, "SANS", "Memory referenced after being freed.", "critical", "static")
d("sans-xml-external-entity", "XML External Entity (XXE)", "SANS Top 25", "backend-api", 0.85, "SANS", "XML parser processes external entities, causing SSRF or file disclosure.", "high", "static+dynamic")

# ── MITRE ATT&CK (50 technique domains) ──────────────────────────────────────
d("mitre-initial-access-phishing", "Phishing (T1566)", "MITRE ATT&CK", "frontend-web", 0.85, "T1566", "Emails containing malicious links or attachments used to gain initial access.", "high", "dynamic")
d("mitre-initial-access-exploit-public", "Exploit Public-Facing Application (T1190)", "MITRE ATT&CK", "backend-api", 0.9, "T1190", "Exploiting vulnerabilities in public-facing applications for initial access.", "critical", "static+dynamic")
d("mitre-initial-access-drive-by", "Drive-By Compromise (T1189)", "MITRE ATT&CK", "frontend-web", 0.85, "T1189", "Exploiting browser vulnerabilities through visited websites.", "high", "dynamic")
d("mitre-initial-access-compromise-supply", "Compromise Software Supply Chain (T1195)", "MITRE ATT&CK", "backend-api", 0.9, "T1195", "Compromising software development or distribution infrastructure.", "critical", "static")
d("mitre-initial-access-trusted-relationship", "Trusted Relationship (T1199)", "MITRE ATT&CK", "infra", 0.8, "T1199", "Exploiting trust relationships between organizations.", "high", "manual-review")
d("mitre-execution-command-scripting", "Command and Scripting Interpreter (T1059)", "MITRE ATT&CK", "backend-api", 0.9, "T1059", "Execution of commands, scripts, or interpreters on a system.", "critical", "static+dynamic")
d("mitre-execution-exploitation-client", "Exploitation for Client Execution (T1203)", "MITRE ATT&CK", "frontend-web", 0.85, "T1203", "Exploiting client software vulnerabilities for code execution.", "high", "static+dynamic")
d("mitre-execution-user-execution", "User Execution (T1204)", "MITRE ATT&CK", "frontend-web", 0.8, "T1204", "Malicious files or links executed by users.", "high", "dynamic")
d("mitre-persistence-boot-autostart", "Boot or Logon Autostart Execution (T1547)", "MITRE ATT&CK", "infra", 0.8, "T1547", "Registry keys or startup folders used for persistence.", "high", "static+dynamic")
d("mitre-persistence-create-modify-process", "Create or Modify System Process (T1543)", "MITRE ATT&CK", "infra", 0.85, "T1543", "Creating or modifying system services or daemons.", "high", "static+dynamic")
d("mitre-persistence-scheduled-task", "Scheduled Task/Job (T1053)", "MITRE ATT&CK", "infra", 0.8, "T1053", "Using scheduled tasks or cron jobs for persistence.", "high", "static+dynamic")
d("mitre-persistence-account-manipulation", "Account Manipulation (T1098)", "MITRE ATT&CK", "backend-api", 0.85, "T1098", "Modifying account credentials or access permissions.", "high", "static+dynamic")
d("mitre-privilege-escalation-process-injection", "Process Injection (T1055)", "MITRE ATT&CK", "native-code", 0.9, "T1055", "Injecting code into running processes for privilege escalation.", "critical", "static")
d("mitre-privilege-escalation-access-token", "Access Token Manipulation (T1134)", "MITRE ATT&CK", "infra", 0.85, "T1134", "Modifying access tokens to elevate privileges.", "high", "static+dynamic")
d("mitre-defense-evasion-obfuscated-files", "Obfuscated Files or Information (T1027)", "MITRE ATT&CK", "native-code", 0.8, "T1027", "Encoding or encrypting data to evade detection.", "high", "static")
d("mitre-defense-evasion-signed-binary", "Signed Binary Proxy Execution (T1218)", "MITRE ATT&CK", "infra", 0.85, "T1218", "Using signed binaries to proxy execution of malicious code.", "high", "static+dynamic")
d("mitre-defense-evasion-disable-security", "Disable or Modify Tools (T1562)", "MITRE ATT&CK", "infra", 0.9, "T1562", "Disabling security tools, logging, or alerting mechanisms.", "critical", "dynamic")
d("mitre-defense-evasion-impair-defenses", "Impair Defenses (T1562)", "MITRE ATT&CK", "infra", 0.9, "T1562", "Modifying or disabling security controls and monitoring.", "critical", "dynamic")
d("mitre-credential-access-credential-dumping", "OS Credential Dumping (T1003)", "MITRE ATT&CK", "infra", 0.9, "T1003", "Extracting credentials from OS storage (SAM, LSA Secrets, /etc/shadow).", "critical", "static+dynamic")
d("mitre-credential-access-brute-force", "Brute Force (T1110)", "MITRE ATT&CK", "backend-api", 0.85, "T1110", "Password guessing, spraying, or credential stuffing attacks.", "high", "dynamic")
d("mitre-credential-access-steal-app-tokens", "Steal Application Access Token (T1528)", "MITRE ATT&CK", "backend-api", 0.85, "T1528", "Stealing OAuth tokens, API keys, or session tokens.", "high", "static+dynamic")
d("mitre-credential-access-network-sniffing", "Network Sniffing (T1040)", "MITRE ATT&CK", "infra", 0.8, "T1040", "Capturing network traffic to extract credentials.", "high", "dynamic")
d("mitre-discovery-network-service", "Network Service Discovery (T1046)", "MITRE ATT&CK", "infra", 0.8, "T1046", "Scanning networks to discover services and open ports.", "high", "dynamic")
d("mitre-discovery-system-info", "System Information Discovery (T1082)", "MITRE ATT&CK", "infra", 0.75, "T1082", "Gathering system information for reconnaissance.", "medium", "dynamic")
d("mitre-discovery-file-directory", "File and Directory Discovery (T1083)", "MITRE ATT&CK", "infra", 0.75, "T1083", "Enumerating files and directories for sensitive data.", "medium", "dynamic")
d("mitre-lateral-movement-remote-services", "Remote Services (T1021)", "MITRE ATT&CK", "infra", 0.85, "T1021", "Using remote services (SSH, RDP, SMB) for lateral movement.", "high", "static+dynamic")
d("mitre-lateral-movement-exploitation-remote", "Exploitation of Remote Services (T1210)", "MITRE ATT&CK", "infra", 0.85, "T1210", "Exploiting vulnerabilities in remote services.", "high", "dynamic")
d("mitre-lateral-movement-use-alternate-auth", "Use Alternate Authentication Material (T1550)", "MITRE ATT&CK", "backend-api", 0.8, "T1550", "Using stolen tokens, cookies, or hashes for lateral movement.", "high", "static+dynamic")
d("mitre-collection-data-staged", "Data Staged (T1074)", "MITRE ATT&CK", "infra", 0.8, "T1074", "Collecting and staging data for exfiltration.", "high", "dynamic")
d("mitre-collection-exfil-over-c2", "Exfiltration Over C2 Channel (T1041)", "MITRE ATT&CK", "infra", 0.85, "T1041", "Exfiltrating data through command-and-control channels.", "high", "dynamic")
d("mitre-exfiltration-over-web-service", "Exfiltration Over Web Service (T1567)", "MITRE ATT&CK", "backend-api", 0.85, "T1567", "Exfiltrating data via cloud storage or web APIs.", "high", "dynamic")
d("mitre-impact-data-destruction", "Data Destruction (T1485)", "MITRE ATT&CK", "infra", 0.9, "T1485", "Destructive attacks targeting data availability.", "critical", "dynamic")
d("mitre-impact-ransomware", "Data Encrypted for Impact (T1486)", "MITRE ATT&CK", "infra", 0.95, "T1486", "Ransomware encrypting data for extortion.", "critical", "dynamic")
d("mitre-impact-website-defacement", "Defacement: Website (T1491)", "MITRE ATT&CK", "frontend-web", 0.8, "T1491", "Modifying web content to display attacker messaging.", "high", "dynamic")
d("mitre-impact-resource-hijacking", "Resource Hijacking (T1496)", "MITRE ATT&CK", "infra", 0.8, "T1496", "Using compromised resources for cryptocurrency mining.", "high", "dynamic")
d("mitre-command-control-encrypted-channel", "Encrypted Channel (T1573)", "MITRE ATT&CK", "infra", 0.85, "T1573", "Using encrypted channels for command and control.", "high", "dynamic")
d("mitre-command-control-application-layer", "Application Layer Protocol (T1071)", "MITRE ATT&CK", "infra", 0.8, "T1071", "Using HTTP, DNS, or other application protocols for C2.", "high", "dynamic")
d("mitre-infiltration-command-control", "Ingress Tool Transfer (T1105)", "MITRE ATT&CK", "infra", 0.85, "T1105", "Downloading tools from external systems.", "high", "dynamic")
d("mitre-resource-development-capabilities", "Develop Capabilities (T1587)", "MITRE ATT&CK", "infra", 0.75, "T1587", "Developing tools, exploits, or infrastructure for operations.", "medium", "manual-review")
d("mitre-resource-development-obtain-capabilities", "Obtain Capabilities (T1588)", "MITRE ATT&CK", "infra", 0.75, "T1588", "Purchasing or downloading exploit tools and infrastructure.", "medium", "manual-review")
d("mitre-resource-development-accounts", "Create Accounts (T1136)", "MITRE ATT&CK", "backend-api", 0.8, "T1136", "Creating accounts for persistence or access.", "high", "static+dynamic")
d("mitre-resource-development-compromise-accounts", "Compromise Accounts (T1586)", "MITRE ATT&CK", "backend-api", 0.85, "T1586", "Taking over legitimate accounts for operations.", "high", "dynamic")

# ── CIS Benchmarks (40 domains) ──────────────────────────────────────────────
d("cis-ubuntu-server", "Ubuntu Server Hardening", "CIS Ubuntu Linux Benchmark", "infra", 0.85, "CIS Ubuntu", "System configuration, file permissions, SSH hardening, and service management for Ubuntu.", "high", "static")
d("cis-centos-server", "CentOS/RHEL Server Hardening", "CIS CentOS/RHEL Benchmark", "infra", 0.85, "CIS CentOS", "System configuration, file permissions, SSH hardening, and service management for CentOS/RHEL.", "high", "static")
d("cis-debian", "Debian Server Hardening", "CIS Debian Benchmark", "infra", 0.85, "CIS Debian", "System configuration and hardening for Debian Linux distributions.", "high", "static")
d("cis-amazon-linux", "Amazon Linux Hardening", "CIS Amazon Linux Benchmark", "infra", 0.85, "CIS Amazon Linux", "System configuration for AWS EC2 instances running Amazon Linux.", "high", "static")
d("cis-docker", "Docker Container Hardening", "CIS Docker Benchmark", "infra", 0.9, "CIS Docker", "Container runtime configuration, image building, and Docker daemon hardening.", "critical", "static")
d("cis-kubernetes", "Kubernetes Hardening", "CIS Kubernetes Benchmark", "infra", 0.9, "CIS Kubernetes", "Master node, worker node, and pod security policies.", "critical", "static+dynamic")
d("cis-nginx", "Nginx Web Server Hardening", "CIS Nginx Benchmark", "infra", 0.85, "CIS Nginx", "TLS configuration, security headers, access controls, and module management.", "high", "static")
d("cis-apache", "Apache HTTP Server Hardening", "CIS Apache Benchmark", "infra", 0.85, "CIS Apache", "Module management, directory permissions, TLS, and logging configuration.", "high", "static")
d("cis-redis", "Redis Hardening", "CIS Redis Benchmark", "infra", 0.8, "CIS Redis", "Authentication, binding, command renaming, and persistence configuration.", "high", "static")
d("cis-mysql", "MySQL Database Hardening", "CIS MySQL Benchmark", "infra", 0.85, "CIS MySQL", "User management, privileges, encryption, and network configuration.", "high", "static")
d("cis-postgresql", "PostgreSQL Hardening", "CIS PostgreSQL Benchmark", "infra", 0.85, "CIS PostgreSQL", "Authentication, privilege management, logging, and SSL configuration.", "high", "static")
d("cis-mongodb", "MongoDB Hardening", "CIS MongoDB Benchmark", "infra", 0.85, "CIS MongoDB", "Authentication, authorization, network configuration, and auditing.", "high", "static")
d("cis-windows-server", "Windows Server Hardening", "CIS Windows Server Benchmark", "infra", 0.85, "CIS Windows", "Account policies, audit policies, user rights, and security options.", "high", "static")
d("cis-azure", "Azure Cloud Hardening", "CIS Azure Benchmark", "cloud-azure", 0.9, "CIS Azure", "IAM, storage, networking, monitoring, and database security in Azure.", "high", "static")
d("cis-aws", "AWS Cloud Hardening", "CIS AWS Benchmark", "cloud-aws", 0.9, "CIS AWS", "IAM, S3, VPC, CloudTrail, and EC2 configuration security.", "high", "static")
d("cis-gcp", "GCP Cloud Hardening", "CIS GCP Benchmark", "cloud-gcp", 0.9, "CIS GCP", "IAM, GCE, GCS, networking, and logging configuration.", "high", "static")
d("cis-macos", "macOS Workstation Hardening", "CIS macOS Benchmark", "desktop-app", 0.75, "CIS macOS", "System settings, firewall, FileVault, and privacy controls.", "medium", "static")
d("cis-ios", "iOS Device Hardening", "CIS iOS Benchmark", "mobile-native", 0.8, "CIS iOS", "Passcode, encryption, app restrictions, and privacy settings.", "high", "static")
d("cis-android", "Android Device Hardening", "CIS Android Benchmark", "mobile-native", 0.8, "CIS Android", "Lock screen, encryption, app permissions, and developer options.", "high", "static")
d("cis-vmware", "VMware ESXi Hardening", "CIS VMware ESXi Benchmark", "infra", 0.85, "CIS VMware", "Service configuration, network policies, and logging.", "high", "static")
d("cis-haproxy", "HAProxy Hardening", "CIS HAProxy Benchmark", "infra", 0.8, "CIS HAProxy", "TLS termination, access controls, rate limiting, and logging.", "high", "static")
d("cis-elasticsearch", "Elasticsearch Hardening", "CIS Elasticsearch Benchmark", "infra", 0.85, "CIS Elasticsearch", "X-Pack security, TLS, authentication, and audit logging.", "high", "static")
d("cis-rabbitmq", "RabbitMQ Hardening", "CIS RabbitMQ Benchmark", "infra", 0.8, "CIS RabbitMQ", "Authentication, authorization, TLS, and management UI access.", "high", "static")
d("cis-kafka", "Kafka Hardening", "CIS Apache Kafka Benchmark", "infra", 0.85, "CIS Kafka", "Authentication, authorization, encryption, and audit logging.", "high", "static")
d("cis-tomcat", "Apache Tomcat Hardening", "CIS Tomcat Benchmark", "infra", 0.85, "CIS Tomcat", "Manager app security, TLS, access logging, and deployment security.", "high", "static")
d("cis-iis", "IIS Web Server Hardening", "CIS IIS Benchmark", "infra", 0.85, "CIS IIS", "Application pool identity, TLS, authentication, and directory browsing.", "high", "static")
d("cis-oracle-db", "Oracle Database Hardening", "CIS Oracle Benchmark", "infra", 0.85, "CIS Oracle", "Account management, privileges, auditing, and network encryption.", "high", "static")
d("cis-sql-server", "SQL Server Hardening", "CIS SQL Server Benchmark", "infra", 0.85, "CIS SQL Server", "Authentication mode, permissions, auditing, and encryption.", "high", "static")
d("cis-suse", "SUSE Linux Hardening", "CIS SUSE Linux Benchmark", "infra", 0.8, "CIS SUSE", "System configuration, file permissions, and service management.", "high", "static")
d("cis-fedora", "Fedora Linux Hardening", "CIS Fedora Benchmark", "infra", 0.8, "CIS Fedora", "System configuration and security hardening for Fedora.", "high", "static")
d("cis-ssh", "SSH Server Hardening", "CIS SSH Benchmark", "infra", 0.85, "CIS SSH", "Key exchange, ciphers, MACs, authentication methods, and access controls.", "high", "static")
d("cis-browsers", "Web Browser Hardening", "CIS Browser Benchmark", "frontend-web", 0.75, "CIS Browsers", "Browser security settings, plugin management, and privacy controls.", "medium", "static")
d("cis-wordpress", "WordPress Hardening", "CIS WordPress Benchmark", "backend-api", 0.85, "CIS WordPress", "File permissions, plugin security, authentication, and updates.", "high", "static")
d("cis-drupal", "Drupal Hardening", "CIS Drupal Benchmark", "backend-api", 0.8, "CIS Drupal", "Module security, file permissions, and database configuration.", "high", "static")
d("cis-istio", "Istio Service Mesh Hardening", "CIS Istio Benchmark", "infra", 0.85, "CIS Istio", "mTLS, authorization policies, telemetry, and gateway configuration.", "high", "static")
d("cis-prometheus", "Prometheus Monitoring Hardening", "CIS Prometheus Benchmark", "infra", 0.75, "CIS Prometheus", "Authentication, TLS, alert manager configuration.", "medium", "static")
d("cis-grafana", "Grafana Dashboard Hardening", "CIS Grafana Benchmark", "infra", 0.8, "CIS Grafana", "Authentication, data source security, and dashboard permissions.", "high", "static")
d("cis-consul", "Consul Hardening", "CIS HashiCorp Consul Benchmark", "infra", 0.8, "CIS Consul", "ACL system, encryption, TLS, and service mesh security.", "high", "static")
d("cis-vault", "HashiCorp Vault Hardening", "CIS Vault Benchmark", "infra", 0.9, "CIS Vault", "Seal/unseal, audit logging, policies, and transit encryption.", "critical", "static")
d("cis-terraform", "Terraform Configuration Hardening", "CIS Terraform Benchmark", "infra", 0.85, "CIS Terraform", "State file encryption, provider authentication, and module security.", "high", "static")

# ── PCI DSS 4.0 (12 domains) ─────────────────────────────────────────────────
d("pci-install-security", "Install and Maintain Security Controls", "PCI DSS 4.0 Req 1", "infra", 0.85, "PCI DSS 1", "Install and maintain network security controls.", "high", "static+dynamic")
d("pci-secure-config", "Secure Systems Configuration", "PCI DSS 4.0 Req 2", "infra", 0.9, "PCI DSS 2", "Apply secure configurations to all system components.", "critical", "static")
d("pci-protect-account", "Protect Stored Account Data", "PCI DSS 4.0 Req 3", "backend-api", 0.95, "PCI DSS 3", "Protect stored cardholder data with encryption and minimization.", "critical", "static")
d("pci-encrypt-transmission", "Encrypt Transmission Over Open Networks", "PCI DSS 4.0 Req 4", "infra", 0.9, "PCI DSS 4", "Encrypt cardholder data during transmission over open networks.", "critical", "static")
d("pci-protect-malware", "Protect Against Malicious Software", "PCI DSS 4.0 Req 5", "infra", 0.85, "PCI DSS 5", "Deploy and maintain anti-malware mechanisms.", "high", "static+dynamic")
d("pci-secure-systems", "Develop and Maintain Secure Systems", "PCI DSS 4.0 Req 6", "backend-api", 0.9, "PCI DSS 6", "Develop and maintain secure systems and software.", "critical", "static+dynamic")
d("pci-restrict-access", "Restrict Access by Business Need-to-Know", "PCI DSS 4.0 Req 7", "infra", 0.9, "PCI DSS 7", "Restrict access to cardholder data by business need-to-know.", "critical", "static+dynamic")
d("pci-identify-auth", "Identify Users and Authenticate Access", "PCI DSS 4.0 Req 8", "backend-api", 0.9, "PCI DSS 8", "Identify and authenticate access to system components.", "critical", "static+dynamic")
d("pci-restrict-physical", "Restrict Physical Access to Cardholder Data", "PCI DSS 4.0 Req 9", "infra", 0.8, "PCI DSS 9", "Restrict physical access to cardholder data.", "high", "manual-review")
d("pci-log-monitor", "Log and Monitor All Access", "PCI DSS 4.0 Req 10", "infra", 0.9, "PCI DSS 10", "Log and monitor all access to network resources and cardholder data.", "critical", "static+dynamic")
d("pci-test-security", "Test Security of Systems Regularly", "PCI DSS 4.0 Req 11", "infra", 0.85, "PCI DSS 11", "Regularly test security of systems and networks.", "high", "dynamic")
d("pci-support-policy", "Maintain Information Security Policy", "PCI DSS 4.0 Req 12", "infra", 0.8, "PCI DSS 12", "Maintain an information security policy for all personnel.", "high", "manual-review")

# ── HIPAA Security Rule (10 domains) ─────────────────────────────────────────
d("hipaa-admin-safeguards", "Administrative Safeguards", "HIPAA Security Rule", "infra", 0.85, "HIPAA", "Security management process, workforce training, and contingency planning.", "high", "manual-review")
d("hipaa-physical-safeguards", "Physical Safeguards", "HIPAA Security Rule", "infra", 0.8, "HIPAA", "Facility access controls, workstation use, and device media controls.", "high", "manual-review")
d("hipaa-technical-access-control", "Technical Access Controls", "HIPAA Security Rule", "backend-api", 0.9, "HIPAA", "Access control, audit controls, integrity, and transmission security for ePHI.", "critical", "static+dynamic")
d("hipaa-ephi-encryption", "ePHI Encryption at Rest", "HIPAA Security Rule", "backend-api", 0.9, "HIPAA", "Encryption of electronic protected health information at rest.", "critical", "static")
d("hipaa-ephi-transmission", "ePHI Transmission Security", "HIPAA Security Rule", "infra", 0.9, "HIPAA", "Encryption and integrity controls for ePHI during transmission.", "critical", "static")
d("hipaa-audit-controls", "Audit Controls", "HIPAA Security Rule", "infra", 0.85, "HIPAA", "Hardware, software, and procedural mechanisms to record and examine access to ePHI.", "high", "static+dynamic")
d("hipaa-integrity-controls", "Data Integrity Controls", "HIPAA Security Rule", "backend-api", 0.85, "HIPAA", "Mechanisms to protect ePHI from improper alteration or destruction.", "high", "static")
d("hipaa-person-auth", "Person or Entity Authentication", "HIPAA Security Rule", "backend-api", 0.9, "HIPAA", "Procedures to verify identity before granting access to ePHI.", "critical", "static+dynamic")
d("hipaa-business-associate", "Business Associate Contracts", "HIPAA Security Rule", "infra", 0.8, "HIPAA", "Written contracts ensuring business associates protect ePHI.", "high", "manual-review")
d("hipaa-breach-notification", "Breach Notification Rule", "HIPAA Security Rule", "infra", 0.85, "HIPAA", "Procedures for detecting, reporting, and responding to data breaches.", "high", "manual-review")

# ── SOC 2 Trust Services Criteria (5 domains) ────────────────────────────────
d("soc2-common-criteria", "Common Criteria (CC)", "SOC 2 TSC", "infra", 0.85, "SOC 2 CC", "Logical and physical access controls, system operations, change management, and risk mitigation.", "high", "static+manual-review")
d("soc2-availability", "Availability", "SOC 2 TSC", "infra", 0.8, "SOC 2 A", "System availability commitments including uptime, disaster recovery, and incident handling.", "high", "static+manual-review")
d("soc2-processing-integrity", "Processing Integrity", "SOC 2 TSC", "backend-api", 0.8, "SOC 2 PI", "System processing is complete, valid, accurate, timely, and authorized.", "high", "static+dynamic")
d("soc2-confidentiality", "Confidentiality", "SOC 2 TSC", "backend-api", 0.85, "SOC 2 C", "Protection of confidential information including encryption, access controls, and disposal.", "high", "static+manual-review")
d("soc2-privacy", "Privacy", "SOC 2 TSC", "backend-api", 0.85, "SOC 2 P", "Collection, use, retention, disclosure, and disposal of personal information.", "high", "static+manual-review")

# ── GDPR (8 domains) ──────────────────────────────────────────────────────────
d("gdpr-lawful-processing", "Lawful Basis for Processing", "GDPR Art 6", "backend-api", 0.9, "GDPR Art 6", "Processing personal data only with a valid lawful basis.", "critical", "static+manual-review")
d("gdpr-consent", "Consent Management", "GDPR Art 7", "backend-api", 0.9, "GDPR Art 7", "Freely given, specific, informed, and unambiguous consent.", "critical", "static+dynamic")
d("gdpr-data-subject-rights", "Data Subject Rights", "GDPR Art 15-22", "backend-api", 0.85, "GDPR Art 15-22", "Access, rectification, erasure, portability, and objection rights.", "high", "static+manual-review")
d("gdpr-data-protection-officer", "Data Protection Officer", "GDPR Art 37-39", "infra", 0.75, "GDPR Art 37-39", "Appointment and duties of a Data Protection Officer.", "medium", "manual-review")
d("gdpr-data-protection-impact", "Data Protection Impact Assessment", "GDPR Art 35", "infra", 0.8, "GDPR Art 35", "Impact assessments for high-risk processing activities.", "high", "manual-review")
d("gdpr-data-breach-notification", "Breach Notification", "GDPR Art 33-34", "infra", 0.9, "GDPR Art 33-34", "Notification to supervisory authority within 72 hours and to affected individuals.", "critical", "manual-review")
d("gdpr-data-minimization", "Data Minimization and Storage Limitation", "GDPR Art 5(1)(c)(e)", "backend-api", 0.85, "GDPR Art 5", "Collect only necessary data and retain only as long as required.", "high", "static")
d("gdpr-international-transfers", "International Data Transfers", "GDPR Art 44-49", "infra", 0.85, "GDPR Art 44-49", "Adequate safeguards for data transfers outside the EU/EEA.", "high", "manual-review")

# ── ISO 27001:2022 (10 domains) ───────────────────────────────────────────────
d("iso27001-organizational", "Organizational Controls (A.5)", "ISO 27001:2022", "infra", 0.85, "ISO A.5", "Policies, roles, segregation of duties, and threat intelligence.", "high", "manual-review")
d("iso27001-people", "People Controls (A.6)", "ISO 27001:2022", "infra", 0.8, "ISO A.6", "Screening, terms of employment, awareness, and disciplinary processes.", "high", "manual-review")
d("iso27001-physical", "Physical Controls (A.7)", "ISO 27001:2022", "infra", 0.75, "ISO A.7", "Physical perimeters, entry controls, and equipment maintenance.", "medium", "manual-review")
d("iso27001-technological", "Technological Controls (A.8)", "ISO 27001:2022", "backend-api", 0.9, "ISO A.8", "Access rights, authentication, cryptography, secure development, and vulnerability management.", "critical", "static+dynamic")
d("iso27001-access-control", "Access Control (A.8.2-A.8.5)", "ISO 27001:2022", "backend-api", 0.9, "ISO A.8.2-A.8.5", "User access management, authentication, and access restrictions.", "critical", "static+dynamic")
d("iso27001-cryptography", "Cryptography (A.8.24)", "ISO 27001:2022", "backend-api", 0.85, "ISO A.8.24", "Policy on cryptographic controls and key management.", "high", "static")
d("iso27001-operations-security", "Operations Security (A.8.8-A.8.16)", "ISO 27001:2022", "infra", 0.85, "ISO A.8.8-A.8.16", "Change management, capacity, malware protection, backup, and logging.", "high", "static+dynamic")
d("iso27001-secure-development", "Secure Development (A.8.25-A.8.34)", "ISO 27001:2022", "backend-api", 0.9, "ISO A.8.25-A.8.34", "Secure development lifecycle, code review, and testing.", "critical", "static+dynamic")
d("iso27001-supplier-security", "Supplier Relationships (A.5.19-A.5.23)", "ISO 27001:2022", "infra", 0.8, "ISO A.5.19-A.5.23", "Information security in supplier agreements and cloud services.", "high", "manual-review")
d("iso27001-incident-management", "Incident Management (A.5.24-A.5.28)", "ISO 27001:2022", "infra", 0.85, "ISO A.5.24-A.5.28", "Incident response planning, detection, assessment, and learning.", "high", "manual-review")

# ── Language & Framework Specific (150 domains) ──────────────────────────────
# React
d("react-xss-dangerously-set", "XSS via dangerouslySetInnerHTML", "React Security", "frontend-web", 0.9, "React XSS", "Using dangerouslySetInnerHTML with user-controlled content enables XSS.", "critical", "static")
d("react-state-tainting", "State Tainting for Injection", "React Security", "frontend-web", 0.8, "React State", "User input flows into state without sanitization, leading to injection when rendered.", "high", "static")
d("react-url-injection", "URL Injection in href/src", "React Security", "frontend-web", 0.85, "React URL", "User-controlled URLs in href, src, or action attributes enable XSS or open redirect.", "high", "static")
d("react-client-side-routing", "Client-Side Route Security", "React Security", "frontend-web", 0.75, "React Router", "Client-side route guards not enforced, allowing direct URL access to protected views.", "medium", "static+dynamic")
d("react-devtools-exposure", "DevTools in Production", "React Security", "frontend-web", 0.7, "React DevTools", "React DevTools or development mode enabled in production builds.", "medium", "static")
d("react-sensitive-data-storage", "Sensitive Data in Client State", "React Security", "frontend-web", 0.85, "React Storage", "Secrets, tokens, or PII stored in component state or localStorage.", "high", "static")
d("react-ssr-data-leak", "SSR Data Leakage", "React Security", "frontend-web", 0.8, "React SSR", "Server-side rendering exposes internal data in HTML source.", "high", "static")
d("react-uncontrolled-inputs", "Uncontrolled Input Security", "React Security", "frontend-web", 0.7, "React Inputs", "Uncontrolled inputs bypass React's data flow, potentially allowing injection.", "medium", "static")
# Vue
d("vue-xss-v-html", "XSS via v-html Directive", "Vue.js Security", "frontend-web", 0.9, "Vue XSS", "Using v-html with user content enables XSS.", "critical", "static")
d("vue-xss-v-bind", "XSS via v-bind with URLs", "Vue.js Security", "frontend-web", 0.8, "Vue v-bind", "Dynamic bindings to href or src with unsanitized user input.", "high", "static")
d("vue-template-injection", "Template Injection in Vue", "Vue.js Security", "frontend-web", 0.85, "Vue Template", "User input inserted into Vue templates or render functions.", "high", "static")
d("vue-reactivity-security", "Reactivity Data Exposure", "Vue.js Security", "frontend-web", 0.75, "Vue Reactivity", "Sensitive data exposed through reactive state in browser.", "medium", "static")
# Angular
d("angular-xss-dom-sanitizer", "XSS Bypass of DomSanitizer", "Angular Security", "frontend-web", 0.9, "Angular XSS", "Bypassing DomSanitizer.bypassSecurityTrust* methods.", "critical", "static")
d("angular-template-injection", "Angular Template Injection", "Angular Security", "frontend-web", 0.85, "Angular Template", "User input in Angular templates leading to code execution.", "high", "static")
d("angular-client-side-navigate", "Client-Side Navigation Security", "Angular Security", "frontend-web", 0.75, "Angular Route", "Missing route guards or lazy-loaded module authorization.", "medium", "static+dynamic")
d("angular-prod-mode", "Angular Production Mode", "Angular Security", "frontend-web", 0.7, "Angular Prod", "Angular debug mode or dev tools enabled in production.", "medium", "static")
# Node.js / Express
d("nodejs-express-body-parsing", "Express Body Parsing Security", "Node.js Security", "backend-api", 0.85, "Node.js Body", "Missing body size limits or improper content-type validation.", "high", "static")
d("nodejs-express-middleware-missing", "Missing Security Middleware", "Node.js Security", "backend-api", 0.85, "Node.js Middleware", "Missing helmet, cors, rate-limiting, or CSRF middleware.", "high", "static")
d("nodejs-express-error-leak", "Express Error Information Leak", "Node.js Security", "backend-api", 0.8, "Node.js Error", "Default Express error handler exposes stack traces and internals.", "high", "static")
d("nodejs-express-session-security", "Express Session Security", "Node.js Security", "backend-api", 0.85, "Node.js Session", "Insecure session configuration (no httpOnly, no secure, weak secret).", "high", "static")
d("nodejs-express-cors-misconfiguration", "Express CORS Misconfiguration", "Node.js Security", "backend-api", 0.85, "Node.js CORS", "Permissive CORS allowing any origin or wildcard with credentials.", "high", "static")
d("nodejs-callback-hell-injection", "Callback Injection in Node.js", "Node.js Security", "backend-api", 0.8, "Node.js Callback", "Callback functions receiving unsanitized user input.", "high", "static")
d("nodejs-prototype-pollution", "Prototype Pollution", "Node.js Security", "backend-api", 0.85, "Node.js Prototype", "Modifying Object.prototype through user-controlled property paths.", "high", "static")
d("nodejs-event-emitter-injection", "Event Emitter Injection", "Node.js Security", "backend-api", 0.75, "Node.js Events", "Untrusted data flowing through EventEmitter without validation.", "medium", "static")
d("nodejs-regex-dos", "Regex Denial of Service (ReDoS)", "Node.js Security", "backend-api", 0.8, "Node.js ReDoS", "User input used in regex patterns vulnerable to catastrophic backtracking.", "high", "static")
# Python / Django
d("django-csrf-protection", "Django CSRF Protection Bypass", "Django Security", "backend-api", 0.9, "Django CSRF", "Missing or incorrectly configured CSRF middleware.", "critical", "static")
d("django-sql-injection", "Django ORM SQL Injection", "Django Security", "backend-api", 0.9, "Django SQL", "Raw SQL queries with string formatting instead of parameterized queries.", "critical", "static")
d("django-xss-template", "Django Template XSS", "Django Security", "frontend-web", 0.85, "Django XSS", "Use of |safe filter or autoescape off with user content.", "high", "static")
d("django-secret-key-exposure", "Django SECRET_KEY Exposure", "Django Security", "backend-api", 0.9, "Django Secret", "SECRET_KEY in version control or hard-coded in settings.", "critical", "static")
d("django-debug-mode", "Django DEBUG=True in Production", "Django Security", "infra", 0.9, "Django Debug", "DEBUG mode enabled in production settings.", "critical", "static")
d("django-clickjacking", "Django Clickjacking Protection", "Django Security", "frontend-web", 0.75, "Django Clickjack", "Missing X-Frame-Options or CSP frame-ancestors.", "medium", "static")
d("django-file-upload", "Django File Upload Security", "Django Security", "backend-api", 0.85, "Django Upload", "Unrestricted file type, size, or content in file uploads.", "high", "static+dynamic")
d("django-sql-injection-raw", "Django Raw SQL Injection", "Django Security", "backend-api", 0.95, "Django Raw SQL", "Using cursor.execute with string interpolation instead of parameterized queries.", "critical", "static")
d("django-password-hashing", "Django Password Hashing", "Django Security", "backend-api", 0.8, "Django Hashing", "Custom password hashers or weak PBKDF2 iterations.", "high", "static")
d("django-session-hijacking", "Django Session Security", "Django Security", "backend-api", 0.85, "Django Session", "Missing SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, or SESSION_EXPIRE_AT_BROWSER_CLOSE.", "high", "static")
# Python / Flask
d("flask-jinja2-xss", "Flask Jinja2 XSS", "Flask Security", "frontend-web", 0.85, "Flask XSS", "Use of |safe filter or Markup() with user input.", "high", "static")
d("flask-session-security", "Flask Session Security", "Flask Security", "backend-api", 0.8, "Flask Session", "Default or weak SECRET_KEY, missing cookie security flags.", "high", "static")
d("flask-sql-injection", "Flask SQLAlchemy Injection", "Flask Security", "backend-api", 0.85, "Flask SQL", "Text() or raw SQL with user input in SQLAlchemy queries.", "high", "static")
d("flask-cors-misconfiguration", "Flask CORS Misconfiguration", "Flask Security", "backend-api", 0.8, "Flask CORS", "Permissive CORS or missing origin validation.", "high", "static")
d("flask-debug-exposure", "Flask Debug Mode Exposure", "Flask Security", "infra", 0.85, "Flask Debug", "Debug mode enabled in production or exposed debugger.", "high", "static")
# Java / Spring
d("spring-sqli-jpa", "Spring JPA SQL Injection", "Spring Security", "backend-api", 0.9, "Spring SQL", "Native queries with string concatenation in Spring Data JPA.", "critical", "static")
d("spring-bean-injection", "Spring Bean Injection Vulnerability", "Spring Security", "backend-api", 0.85, "Spring Bean", "Unvalidated bean properties allowing injection attacks.", "high", "static")
d("spring-security-misconfig", "Spring Security Misconfiguration", "Spring Security", "backend-api", 0.9, "Spring Config", "Disabled CSRF, permissive CORS, or missing authentication filters.", "critical", "static")
d("spring-deserialization", "Spring Deserialization Vulnerability", "Spring Security", "backend-api", 0.85, "Spring Deser", "Unsafe deserialization in Spring RPC endpoints.", "high", "static")
d("spring-actuator-exposure", "Spring Actuator Exposure", "Spring Security", "infra", 0.9, "Spring Actuator", "Exposed actuator endpoints leaking system information.", "critical", "static+dynamic")
d("spring-el-injection", "Spring Expression Language Injection", "Spring Security", "backend-api", 0.9, "Spring EL", "User input in SpEL expressions leading to code execution.", "critical", "static")
# .NET
d("dotnet-viewstate-tampering", ".NET ViewState Tampering", ".NET Security", "frontend-web", 0.85, ".NET ViewState", "ViewState not signed or encrypted, allowing tampering.", "high", "static")
d("dotnet-sql-injection", ".NET SQL Injection", ".NET Security", "backend-api", 0.9, ".NET SQL", "String concatenation in SqlCommand or Entity Framework LINQ injection.", "critical", "static")
d("dotnet-auth-bypass", ".NET Authentication Bypass", ".NET Security", "backend-api", 0.9, ".NET Auth", "Missing [Authorize] attributes or permissive authorization.", "critical", "static+dynamic")
d("dotnet-deserialization", ".NET Insecure Deserialization", ".NET Security", "backend-api", 0.9, ".NET Deser", "BinaryFormatter or TypeNameHandling allowing type confusion.", "critical", "static")
d("dotnet-xss-razor", ".NET Razor XSS", ".NET Security", "frontend-web", 0.85, ".NET XSS", "Html.Raw() with user input or missing output encoding.", "high", "static")
# Go
d("go-sql-injection", "Go SQL Injection", "Go Security", "backend-api", 0.9, "Go SQL", "String formatting in SQL queries instead of parameterized queries.", "critical", "static")
d("go-command-injection", "Go Command Injection", "Go Security", "backend-api", 0.9, "Go Command", "os/exec with user-controlled arguments.", "critical", "static+dynamic")
d("go-unsafe-conversion", "Go Unsafe Pointer Conversion", "Go Security", "backend-api", 0.8, "Go Unsafe", "unsafe.Pointer usage leading to memory corruption.", "high", "static")
d("go-path-traversal", "Go Path Traversal", "Go Security", "backend-api", 0.85, "Go Path", "filepath.Join with user input without validation.", "high", "static+dynamic")
d("go-race-condition", "Go Race Condition", "Go Security", "backend-api", 0.8, "Go Race", "Concurrent goroutine access to shared state without synchronization.", "high", "static")
d("go-ssrf", "Go SSRF", "Go Security", "backend-api", 0.85, "Go SSRF", "http.Get/Post with user-controlled URLs.", "high", "static+dynamic")
d("go-template-injection", "Go Template Injection", "Go Security", "backend-api", 0.85, "Go Template", "User input in Go text/template or html/template execution.", "high", "static")
d("go-crypto-weak", "Go Cryptographic Weakness", "Go Security", "backend-api", 0.8, "Go Crypto", "Use of math/rand instead of crypto/rand or weak hash functions.", "high", "static")
# Rust
d("rust-unsafe-raw-pointer", "Rust Unsafe Raw Pointer Usage", "Rust Security", "native-code", 0.9, "Rust Unsafe", "Unsafe blocks with raw pointer dereference without bounds checking.", "critical", "static")
d("rust-buffer-overflow", "Rust Buffer Overflow via Unsafe", "Rust Security", "native-code", 0.9, "Rust Buffer", "unsafe code bypassing Rust's memory safety guarantees.", "critical", "static")
d("rust-panic-dos", "Rust Panic DoS", "Rust Security", "backend-api", 0.8, "Rust Panic", "unwrap() or expect() on untrusted data causing panics.", "high", "static")
d("rust-integer-overflow", "Rust Integer Overflow", "Rust Security", "native-code", 0.85, "Rust Overflow", "Arithmetic operations in release mode wrapping without checks.", "high", "static")
d("rust-dependency-confusion", "Rust Dependency Confusion", "Rust Security", "backend-api", 0.8, "Rust Deps", "Cargo.toml with ambiguous or hijackable crate names.", "high", "static")
# Ruby / Rails
d("rails-sql-injection", "Rails ActiveRecord SQL Injection", "Ruby on Rails Security", "backend-api", 0.9, "Rails SQL", "where() with string interpolation or find_by_sql with user input.", "critical", "static")
d("rails-xss-erb", "Rails ERB XSS", "Ruby on Rails Security", "frontend-web", 0.85, "Rails XSS", "raw() or html_safe with user content in ERB templates.", "high", "static")
d("rails-mass-assignment", "Rails Mass Assignment", "Ruby on Rails Security", "backend-api", 0.85, "Rails Mass", "Strong parameters not properly configured allowing attribute injection.", "high", "static")
d("rails-deserialization", "Rails Deserialization Vulnerability", "Ruby on Rails Security", "backend-api", 0.85, "Rails Deser", "YAML or Marshal deserialization of untrusted data.", "high", "static")
d("rails-devise-security", "Rails Devise Configuration", "Ruby on Rails Security", "backend-api", 0.8, "Rails Devise", "Insecure Devise configuration or missing confirmable/lockable modules.", "high", "static")
# PHP / Laravel
d("laravel-sql-injection", "Laravel Query Builder Injection", "Laravel Security", "backend-api", 0.9, "Laravel SQL", "DB::raw() or whereRaw() with user input.", "critical", "static")
d("laravel-mass-assignment", "Laravel Mass Assignment", "Laravel Security", "backend-api", 0.85, "Laravel Mass", "$fillable or $guarded not properly configured.", "high", "static")
d("laravel-blade-xss", "Laravel Blade XSS", "Laravel Security", "frontend-web", 0.85, "Laravel XSS", " {!! !!} unescaped output with user content in Blade templates.", "high", "static")
d("laravel-debug-mode", "Laravel Debug Mode", "Laravel Security", "infra", 0.85, "Laravel Debug", "APP_DEBUG=true in production exposing stack traces.", "high", "static")
d("laravel-encryption-key", "Laravel Encryption Key Exposure", "Laravel Security", "backend-api", 0.9, "Laravel Key", "APP_KEY in version control or weak encryption key.", "critical", "static")
d("laravel-unsafe-redirect", "Laravel Open Redirect", "Laravel Security", "backend-api", 0.75, "Laravel Redirect", "Redirect with unvalidated URL parameter.", "medium", "static+dynamic")
# PHP General
d("php-inclusion-remote", "PHP Remote File Inclusion", "PHP Security", "backend-api", 0.95, "PHP RFI", "include/require with user-controlled URL.", "critical", "static+dynamic")
d("php-inclusion-local", "PHP Local File Inclusion", "PHP Security", "backend-api", 0.9, "PHP LFI", "include/require with user-controlled path.", "critical", "static+dynamic")
d("php-unserialize", "PHP Unsafe Deserialization", "PHP Security", "backend-api", 0.9, "PHP Deser", "unserialize() with untrusted data.", "critical", "static")
d("php-file-upload-exec", "PHP File Upload to RCE", "PHP Security", "backend-api", 0.9, "PHP Upload", "Uploaded files executable from web directory.", "critical", "static+dynamic")
d("php-type-juggling", "PHP Type Juggling", "PHP Security", "backend-api", 0.8, "PHP Type", "Loose comparison (==) with user input leading to auth bypass.", "high", "static")
d("php-config-expose", "PHP Configuration Exposure", "PHP Security", "infra", 0.8, "PHP Config", "phpinfo() accessible or display_errors enabled.", "high", "static")
# C/C++
d("c-cpp-buffer-overflow", "C/C++ Buffer Overflow", "C/C++ Security", "native-code", 0.95, "C/C++ Buffer", "strcpy, sprintf, gets without bounds checking.", "critical", "static")
d("c-cpp-format-string", "C/C++ Format String Vulnerability", "C/C++ Security", "native-code", 0.9, "C/C++ Format", "printf/fprintf with user-controlled format string.", "critical", "static")
d("c-cpp-memory-leak", "C/C++ Memory Leak", "C/C++ Security", "native-code", 0.8, "C/C++ Leak", "malloc without corresponding free leading to resource exhaustion.", "high", "static")
d("c-cpp-double-free", "C/C++ Double Free", "C/C++ Security", "native-code", 0.9, "C/C++ Free", "Freeing memory twice leading to heap corruption.", "critical", "static")
d("c-cpp-integer-overflow", "C/C++ Integer Overflow", "C/C++ Security", "native-code", 0.85, "C/C++ Int", "Arithmetic overflow leading to buffer overflow or logic errors.", "high", "static")
d("c-cpp-uninitialized-memory", "C/C++ Uninitialized Memory", "C/C++ Security", "native-code", 0.8, "C/C++ Uninit", "Use of uninitialized stack or heap variables.", "high", "static")
# Java
d("java-dep-jndi-injection", "Java JNDI Injection", "Java Security", "backend-api", 0.95, "Java JNDI", "JNDI lookup with user-controlled input leading to RCE (Log4Shell).", "critical", "static+dynamic")
d("java-xss-jsp", "Java JSP XSS", "Java Security", "frontend-web", 0.85, "Java XSS", "Unescaped output in JSP pages with user input.", "high", "static")
d("java-deserialization", "Java Insecure Deserialization", "Java Security", "backend-api", 0.9, "Java Deser", "ObjectInputStream.readObject() with untrusted data.", "critical", "static")
d("java-sql-injection-jdbc", "Java JDBC SQL Injection", "Java Security", "backend-api", 0.9, "Java SQL", "Statement.executeQuery with string concatenation.", "critical", "static")
d("java-xml-external-entity", "Java XXE", "Java Security", "backend-api", 0.85, "Java XXE", "XML parser processing external entities.", "high", "static")
d("java-unsafe-reflection", "Java Unsafe Reflection", "Java Security", "backend-api", 0.85, "Java Reflect", "Dynamic method invocation with user-controlled class/method names.", "high", "static")
# TypeScript
d("ts-strict-mode-bypass", "TypeScript Strict Mode Bypass", "TypeScript Security", "backend-api", 0.7, "TS Strict", "Type assertions or any type bypassing compile-time checks.", "medium", "static")
d("ts-decorator-injection", "TypeScript Decorator Injection", "TypeScript Security", "backend-api", 0.8, "TS Decorator", "User-controlled decorator metadata leading to code execution.", "high", "static")
# Svelte
d("svelte-html-injection", "Svelte HTML Injection", "Svelte Security", "frontend-web", 0.85, "Svelte HTML", "Use of {@html} with user content enabling XSS.", "high", "static")
d("svelte-reactive-leak", "Svelte Reactive Data Leak", "Svelte Security", "frontend-web", 0.75, "Svelte Reactive", "Sensitive data exposed through reactive bindings in browser.", "medium", "static")
# Next.js
d("nextjs-ssr-data-leak", "Next.js SSR Data Leakage", "Next.js Security", "frontend-web", 0.85, "Next.js SSR", "Server-side props leaking internal data in page source.", "high", "static")
d("nextjs-api-routes-auth", "Next.js API Route Authentication", "Next.js Security", "backend-api", 0.9, "Next.js API", "Missing authentication middleware on API routes.", "critical", "static+dynamic")
d("nextjs-middleware-bypass", "Next.js Middleware Bypass", "Next.js Security", "backend-api", 0.85, "Next.js Middleware", "Middleware auth checks bypassable via direct route access.", "high", "static+dynamic")
d("nextjs-image-unoptimized", "Next.js Image Security", "Next.js Security", "frontend-web", 0.75, "Next.js Image", "Unoptimized images or missing domain allowlist in next.config.", "medium", "static")
# Nuxt
d("nuxt-ssr-data-leak", "Nuxt SSR Data Leakage", "Nuxt Security", "frontend-web", 0.85, "Nuxt SSR", "Sensitive data in __NUXT__ state exposed to client.", "high", "static")
d("nuxt-middleware-auth", "Nuxt Middleware Authentication", "Nuxt Security", "backend-api", 0.85, "Nuxt Auth", "Missing or bypassable middleware authentication.", "high", "static+dynamic")
# FastAPI
d("fastapi-dependency-injection", "FastAPI Dependency Injection Security", "FastAPI Security", "backend-api", 0.85, "FastAPI DI", "Unsafe dependency injection allowing injection attacks.", "high", "static")
d("fastapi-openapi-exposure", "FastAPI OpenAPI Exposure", "FastAPI Security", "infra", 0.8, "FastAPI OpenAPI", "OpenAPI docs exposed without authentication in production.", "high", "static")
d("fastapi-cors-misconfig", "FastAPI CORS Misconfiguration", "FastAPI Security", "backend-api", 0.85, "FastAPI CORS", "Permissive CORS or missing origin validation.", "high", "static")
# Express / Fastify / Koa
d("fastify-serialization", "Fastify Serialization Security", "Node.js Security", "backend-api", 0.8, "Fastify Serial", "Prototype pollution through serializer manipulation.", "high", "static")
d("koa-middleware-skip", "Koa Middleware Skip", "Node.js Security", "backend-api", 0.8, "Koa Middleware", "Missing or bypassable authentication middleware.", "high", "static+dynamic")
# GraphQL
d("graphql-introspection", "GraphQL Introspection Exposure", "GraphQL Security", "backend-api", 0.85, "GraphQL Intro", "Introspection enabled in production exposing entire schema.", "high", "static+dynamic")
d("graphql-injection", "GraphQL Query Injection", "GraphQL Security", "backend-api", 0.9, "GraphQL Inject", "User input in GraphQL resolvers without sanitization.", "critical", "static+dynamic")
d("graphql-n-plus-one", "GraphQL N+1 Query", "GraphQL Security", "backend-api", 0.8, "GraphQL N+1", "Unbatched database queries leading to performance degradation.", "high", "static")
d("graphql-depth-limit", "GraphQL Query Depth", "GraphQL Security", "backend-api", 0.85, "GraphQL Depth", "Missing query depth limit allowing resource exhaustion.", "high", "static+dynamic")
d("graphql-authorization", "GraphQL Authorization Bypass", "GraphQL Security", "backend-api", 0.9, "GraphQL Auth", "Missing field-level authorization in GraphQL resolvers.", "critical", "static+dynamic")
d("graphql-cost-analysis", "GraphQL Cost Analysis", "GraphQL Security", "backend-api", 0.8, "GraphQL Cost", "No cost analysis allowing expensive queries to DoS the server.", "high", "dynamic")
# gRPC
d("grpc-insecure-connection", "gRPC Insecure Connection", "gRPC Security", "backend-api", 0.85, "gRPC TLS", "gRPC without TLS or with insecure channel credentials.", "high", "static")
d("grpc-auth-bypass", "gRPC Authentication Bypass", "gRPC Security", "backend-api", 0.85, "gRPC Auth", "Missing or weak interceptors for authentication.", "high", "static+dynamic")
d("grpc-reflection-exposure", "gRPC Server Reflection", "gRPC Security", "infra", 0.8, "gRPC Reflect", "gRPC reflection service enabled in production.", "high", "static")
d("grpc-message-size", "gRPC Message Size Limit", "gRPC Security", "backend-api", 0.75, "gRPC Size", "Missing max message size allowing memory exhaustion.", "medium", "static")
# WebAssembly
d("wasm-memory-safety", "WebAssembly Memory Safety", "WebAssembly Security", "frontend-web", 0.85, "WASM Memory", "Out-of-bounds memory access in WASM modules.", "high", "static")
d("wasm-unsafe-imports", "WebAssembly Unsafe Imports", "WebAssembly Security", "frontend-web", 0.8, "WASM Imports", "WASM importing host functions without validation.", "high", "static")
# Serverless
d("serverless-event-injection", "Serverless Event Injection", "Serverless Security", "backend-api", 0.85, "Serverless Inject", "Unvalidated event data triggering code execution in Lambda/Functions.", "high", "static+dynamic")
d("serverless-permission-overreach", "Serverless Over-Permissive IAM", "Serverless Security", "infra", 0.9, "Serverless IAM", "Lambda/Function IAM roles with excessive permissions.", "critical", "static")
d("serverless-secrets-exposure", "Serverless Secrets Exposure", "Serverless Security", "infra", 0.85, "Serverless Secrets", "Secrets in environment variables visible in console or logs.", "high", "static")
d("serverless-insecure-dependencies", "Serverless Dependency Risks", "Serverless Security", "backend-api", 0.8, "Serverless Deps", "Vulnerable dependencies in serverless deployment packages.", "high", "static")
# Edge Computing
d("edge-function-injection", "Edge Function Injection", "Edge Computing Security", "backend-api", 0.85, "Edge Inject", "User input in Edge/CDN worker functions without validation.", "high", "static+dynamic")
d("edge-cache-poisoning", "Edge Cache Poisoning", "Edge Computing Security", "infra", 0.85, "Edge Cache", "Cache key manipulation leading to serving poisoned content.", "high", "dynamic")
d("edge-origin-bypass", "Edge Origin Bypass", "Edge Computing Security", "infra", 0.8, "Edge Origin", "Bypassing edge protection to access origin directly.", "high", "dynamic")
# PWA
d("pwa-service-worker-security", "PWA Service Worker Security", "PWA Security", "frontend-web", 0.8, "PWA SW", "Service worker caching sensitive data or serving stale content.", "high", "static")
d("pwa-push-notification", "PWA Push Notification Security", "PWA Security", "frontend-web", 0.75, "PWA Push", "Push notification subscription without proper VAPID key validation.", "medium", "static+dynamic")
d("pwa-offline-storage", "PWA Offline Storage Security", "PWA Security", "frontend-web", 0.8, "PWA Storage", "Sensitive data cached in IndexedDB or Cache API without encryption.", "high", "static")
# Browser Extensions
d("extension-content-script-injection", "Extension Content Script Injection", "Browser Extension Security", "frontend-web", 0.85, "Ext Content", "Content scripts accessing page DOM without validation.", "high", "static")
d("extension-message-passing", "Extension Message Passing", "Browser Extension Security", "frontend-web", 0.8, "Ext Message", "Insecure message passing between extension components.", "high", "static")
d("extension-remote-code", "Extension Remote Code Execution", "Browser Extension Security", "frontend-web", 0.9, "Ext RCE", "Loading and executing remote code from CDN or API.", "critical", "static")
# Desktop Apps
d("electron-remote-module", "Electron Remote Module", "Desktop App Security", "desktop-app", 0.9, "Electron Remote", "Using Electron remote module enabling full system access from renderer.", "critical", "static")
d("electron-node-integration", "Electron Node Integration", "Desktop App Security", "desktop-app", 0.9, "Electron Node", "nodeIntegration enabled in BrowserWindow allowing Node.js from renderer.", "critical", "static")
d("electron-context-isolation", "Electron Context Isolation", "Desktop App Security", "desktop-app", 0.85, "Electron Context", "Missing contextIsolation exposing preload script to renderer.", "high", "static")
d("electron-shell-open", "Electron Shell Open", "Desktop App Security", "desktop-app", 0.85, "Electron Shell", "shell.openExternal with user-controlled URL enabling command execution.", "high", "static+dynamic")
d("electron-protocol-handler", "Electron Protocol Handler", "Desktop App Security", "desktop-app", 0.8, "Electron Proto", "Custom protocol handler with insufficient validation.", "high", "static")
d("tauri-command-injection", "Tauri Command Injection", "Desktop App Security", "desktop-app", 0.85, "Tauri Cmd", "Tauri commands receiving unvalidated input from frontend.", "high", "static")
d("tauri-permission-scope", "Tauri Permission Scope", "Desktop App Security", "desktop-app", 0.8, "Tauri Scope", "Overly permissive Tauri plugin permissions.", "high", "static")
# Build & CI/CD
d("cicd-secret-exposure", "CI/CD Secret Exposure", "CI/CD Security", "infra", 0.9, "CI/CD Secrets", "Secrets in pipeline variables, logs, or artifact metadata.", "critical", "static+dynamic")
d("cicd-pipeline-injection", "CI/CD Pipeline Injection", "CI/CD Security", "infra", 0.9, "CI/CD Inject", "Untrusted input in CI/CD pipeline steps leading to code execution.", "critical", "static+dynamic")
d("cicd-artifact-tampering", "CI/CD Artifact Tampering", "CI/CD Security", "infra", 0.85, "CI/CD Artifact", "Build artifacts not signed or verified before deployment.", "high", "static")
d("cicd-credential-leak", "CI/CD Credential Leak", "CI/CD Security", "infra", 0.9, "CI/CD Creds", "Credentials committed to repos or stored in plaintext pipeline configs.", "critical", "static")
d("cicd-dependency-confusion", "CI/CD Dependency Confusion", "CI/CD Security", "infra", 0.85, "CI/CD Deps", "Internal package names used in public registries allowing hijacking.", "high", "static")
d("cicd-insufficient-isolation", "CI/CD Insufficient Isolation", "CI/CD Security", "infra", 0.85, "CI/CD Iso", "Shared runners or insufficient job isolation allowing cross-project contamination.", "high", "static")
d("cicd-privilege-escalation", "CI/CD Privilege Escalation", "CI/CD Security", "infra", 0.9, "CI/CD Priv", "Pipeline running with elevated privileges beyond what's needed.", "critical", "static")
d("cicd-unsafe-checkout", "CI/CD Unsafe Checkout", "CI/CD Security", "infra", 0.85, "CI/CD Checkout", "Checking out untrusted code or PRs without validation.", "high", "static")
d("cicd-cache-poisoning", "CI/CD Cache Poisoning", "CI/CD Security", "infra", 0.8, "CI/CD Cache", "Dependency or build cache manipulation leading to supply chain attacks.", "high", "dynamic")
d("cicd-workflow-injection", "GitHub Actions Workflow Injection", "CI/CD Security", "infra", 0.9, "GH Actions", "Untrusted input in GitHub Actions workflow expressions leading to code execution.", "critical", "static+dynamic")
# Git & Version Control
d("git-secrets-commit", "Secrets in Git Commits", "Git Security", "infra", 0.9, "Git Secrets", "API keys, passwords, or tokens committed to version control.", "critical", "static")
d("git-branch-protection", "Git Branch Protection", "Git Security", "infra", 0.85, "Git Branch", "Missing branch protection rules allowing direct push to main.", "high", "static")
d("git-signed-commits", "Git Signed Commits", "Git Security", "infra", 0.75, "Git Signed", "Unsigned commits allowing impersonation.", "medium", "static")
d("git-lfs-exposure", "Git LFS Data Exposure", "Git Security", "infra", 0.8, "Git LFS", "Large files with sensitive data stored in Git LFS accessible to unauthorized users.", "high", "static")
# Supply Chain
d("supply-chain-malicious-package", "Malicious Package Injection", "Supply Chain Security", "backend-api", 0.95, "Supply Chain", "Typosquatting or dependency confusion attacks via package registries.", "critical", "static")
d("supply-chain-typosquatting", "Typosquatting", "Supply Chain Security", "backend-api", 0.9, "Supply Chain", "Package names similar to popular libraries used to distribute malware.", "critical", "static")
d("supply-chain-dependency-confusion", "Dependency Confusion", "Supply Chain Security", "backend-api", 0.9, "Supply Chain", "Internal package names published to public registries, hijacking builds.", "critical", "static")
d("supply-chain-solarwinds", "SolarWinds-Style Attack", "Supply Chain Security", "backend-api", 0.9, "Supply Chain", "Compromised build system injecting malicious code into legitimate packages.", "critical", "static")
d("supply-chain-repo-jacking", "Repository Takeover", "Supply Chain Security", "backend-api", 0.85, "Supply Chain", "Abandoned or transferred repositories with existing dependents.", "high", "static")
d("supply-chain-lock-file", "Lock File Manipulation", "Supply Chain Security", "backend-api", 0.85, "Supply Chain", "Tampered lock files (package-lock.json, go.sum) resolving to malicious versions.", "high", "static")
d("supply-chain-private-registry", "Private Registry Exposure", "Supply Chain Security", "infra", 0.8, "Supply Chain", "Internal package registry exposed publicly or with weak authentication.", "high", "static+dynamic")
d("supply-chain-postinstall", "Post-Install Script Abuse", "Supply Chain Security", "backend-api", 0.9, "Supply Chain", "Malicious postinstall scripts in packages executing arbitrary code.", "critical", "static")
# Secrets Management
d("secrets-env-exposure", "Secrets in Environment Variables", "Secrets Management", "infra", 0.85, "Secrets Env", "Sensitive credentials stored in plaintext environment variables.", "high", "static")
d("secrets-file-exposure", "Secrets in Configuration Files", "Secrets Management", "infra", 0.9, "Secrets File", "Secrets committed in config files, .env, or YAML.", "critical", "static")
d("secrets-logging-exposure", "Secrets in Logs", "Secrets Management", "backend-api", 0.85, "Secrets Log", "Secrets accidentally logged in application output or error messages.", "high", "static")
d("secrets-rotation", "Secret Rotation", "Secrets Management", "infra", 0.8, "Secrets Rotate", "No regular rotation of API keys, tokens, or certificates.", "high", "static+manual-review")
d("secrets-in-transit", "Secrets in Transit", "Secrets Management", "infra", 0.85, "Secrets Transit", "Secrets transmitted in plaintext between services.", "high", "static")
d("secrets-in-artifacts", "Secrets in Build Artifacts", "Secrets Management", "infra", 0.85, "Secrets Artifact", "Secrets embedded in Docker images, JARs, or other build artifacts.", "high", "static")
d("secrets-in-source", "Secrets in Source Code", "Secrets Management", "backend-api", 0.95, "Secrets Source", "Hardcoded passwords, API keys, or tokens in source files.", "critical", "static")
d("secrets-in-backup", "Secrets in Backups", "Secrets Management", "infra", 0.8, "Secrets Backup", "Unencrypted backups containing plaintext secrets.", "high", "static")
# Configuration
d("config-spring-boot", "Spring Boot Configuration", "Configuration Security", "infra", 0.85, "Config Spring", "application.properties with sensitive values or debug endpoints enabled.", "high", "static")
d("config-dotenv-exposure", ".env File Exposure", "Configuration Security", "infra", 0.9, "Config Env", ".env file committed to repo or served by web server.", "critical", "static+dynamic")
d("config-yaml-secrets", "YAML Configuration Secrets", "Configuration Security", "infra", 0.85, "Config YAML", "Secrets in docker-compose.yml, kubernetes manifests, or CI configs.", "high", "static")
d("config-json-secrets", "JSON Configuration Secrets", "Configuration Security", "infra", 0.85, "Config JSON", "Secrets in package.json, config.json, or settings files.", "high", "static")
d("config-ini-secrets", "INI Configuration Secrets", "Configuration Security", "infra", 0.8, "Config INI", "Secrets in .ini, .cfg, or .conf files.", "high", "static")
d("config-toml-secrets", "TOML Configuration Secrets", "Configuration Security", "infra", 0.8, "Config TOML", "Secrets in pyproject.toml, Cargo.toml, or config.toml.", "high", "static")
# Cloud Security (50 domains)
d("cloud-aws-s3-public", "AWS S3 Public Bucket", "Cloud Security AWS", "cloud-aws", 0.9, "AWS S3", "S3 bucket with public read or write ACL.", "critical", "static+dynamic")
d("cloud-aws-iam-overpriv", "AWS IAM Over-Permission", "Cloud Security AWS", "cloud-aws", 0.9, "AWS IAM", "IAM policies with Action: * or Resource: * granting excessive access.", "critical", "static")
d("cloud-aws-lambda-env", "AWS Lambda Environment Secrets", "Cloud Security AWS", "cloud-aws", 0.85, "AWS Lambda", "Secrets stored in Lambda environment variables visible in console.", "high", "static")
d("cloud-aws-ec2-public", "AWS EC2 Public Instance", "Cloud Security AWS", "cloud-aws", 0.85, "AWS EC2", "EC2 instance with public IP and open security group rules.", "high", "static+dynamic")
d("cloud-aws-rds-public", "AWS RDS Public Database", "Cloud Security AWS", "cloud-aws", 0.9, "AWS RDS", "RDS instance accessible from public internet.", "critical", "static+dynamic")
d("cloud-aws-cloudtrail", "AWS CloudTrail Configuration", "Cloud Security AWS", "cloud-aws", 0.85, "AWS CloudTrail", "CloudTrail not enabled or logging to unencrypted S3 bucket.", "high", "static")
d("cloud-aws-kms", "AWS KMS Key Management", "Cloud Security AWS", "cloud-aws", 0.85, "AWS KMS", "KMS key policies allowing unauthorized access or no key rotation.", "high", "static")
d("cloud-aws-ecs", "AWS ECS/Fargate Security", "Cloud Security AWS", "cloud-aws", 0.85, "AWS ECS", "Container with privileged mode or excessive capabilities.", "high", "static+dynamic")
d("cloud-aws-api-gateway", "AWS API Gateway Security", "Cloud Security AWS", "cloud-aws", 0.85, "AWS API GW", "Missing authentication, rate limiting, or WAF on API Gateway.", "high", "static+dynamic")
d("cloud-aws-sqs", "AWS SQS Security", "Cloud Security AWS", "cloud-aws", 0.8, "AWS SQS", "SQS queue with overly permissive access policies.", "high", "static")
d("cloud-azure-storage", "Azure Blob Storage Security", "Cloud Security Azure", "cloud-azure", 0.85, "Azure Storage", "Public blob container or missing encryption at rest.", "high", "static+dynamic")
d("cloud-azure-iam", "Azure IAM Over-Permission", "Cloud Security Azure", "cloud-azure", 0.9, "Azure IAM", "Contributor or Owner role assigned to non-admin service principals.", "critical", "static")
d("cloud-azure-keyvault", "Azure Key Vault Security", "Cloud Security Azure", "cloud-azure", 0.9, "Azure KV", "Key Vault with weak access policies or soft delete disabled.", "critical", "static")
d("cloud-azure-functions", "Azure Functions Security", "Cloud Security Azure", "cloud-azure", 0.85, "Azure Func", "Function with HTTP trigger and no authentication.", "high", "static+dynamic")
d("cloud-azure-sql", "Azure SQL Security", "Cloud Security Azure", "cloud-azure", 0.85, "Azure SQL", "Azure SQL with public endpoint or weak TDE configuration.", "high", "static")
d("cloud-azure-devops", "Azure DevOps Security", "Cloud Security Azure", "cloud-azure", 0.8, "Azure DevOps", "Pipeline with variable groups containing secrets in plaintext.", "high", "static")
d("cloud-gcp-gcs", "GCP Cloud Storage Security", "Cloud Security GCP", "cloud-gcp", 0.85, "GCP GCS", "Public bucket or missing encryption configuration.", "high", "static+dynamic")
d("cloud-gcp-iam", "GCP IAM Over-Permission", "Cloud Security GCP", "cloud-gcp", 0.9, "GCP IAM", "roles/editor or roles/owner granted to service accounts.", "critical", "static")
d("cloud-gcp-functions", "GCP Cloud Functions Security", "Cloud Security GCP", "cloud-gcp", 0.85, "GCP Func", "Function with unauthenticated HTTP trigger.", "high", "static+dynamic")
d("cloud-gcp-compute", "GCP Compute Engine Security", "Cloud Security GCP", "cloud-gcp", 0.85, "GCP Compute", "VM with default service account or open firewall rules.", "high", "static+dynamic")
d("cloud-gcp-gke", "GCP GKE Security", "Cloud Security GCP", "cloud-gcp", 0.9, "GCP GKE", "GKE cluster with legacy auth, public endpoint, or weak RBAC.", "critical", "static+dynamic")
d("cloud-gcp-bigquery", "GCP BigQuery Security", "Cloud Security GCP", "cloud-gcp", 0.8, "GCP BigQuery", "BigQuery dataset with public access or missing column-level security.", "high", "static")
d("cloud-gcp-secrets-manager", "GCP Secret Manager Security", "Cloud Security GCP", "cloud-gcp", 0.85, "GCP Secrets", "Secret without versioning, rotation, or proper IAM bindings.", "high", "static")
# Container & Orchestration (30 domains)
d("container-image-vulnerabilities", "Container Image Vulnerabilities", "Container Security", "infra", 0.9, "Container Image", "Container images with known CVEs from base images or dependencies.", "critical", "static")
d("container-privileged-mode", "Container Privileged Mode", "Container Security", "infra", 0.9, "Container Priv", "Running containers with --privileged flag or excessive capabilities.", "critical", "static+dynamic")
d("container-root-user", "Container Running as Root", "Container Security", "infra", 0.85, "Container Root", "Container running as root user instead of non-root UID.", "high", "static")
d("container-network-exposure", "Container Network Exposure", "Container Security", "infra", 0.85, "Container Net", "Container ports exposed to host network or public interface.", "high", "static+dynamic")
d("container-secret-mount", "Container Secret Mounting", "Container Security", "infra", 0.85, "Container Secret", "Secrets mounted as volumes or passed via environment variables.", "high", "static")
d("container-escape", "Container Escape Vulnerability", "Container Security", "infra", 0.95, "Container Escape", "Kernel or runtime vulnerabilities allowing container escape.", "critical", "static+dynamic")
d("container-resource-limits", "Container Resource Limits", "Container Security", "infra", 0.8, "Container Resource", "Missing CPU/memory limits allowing resource exhaustion.", "high", "static")
d("container-read-only-fs", "Container Read-Only Filesystem", "Container Security", "infra", 0.8, "Container FS", "Container filesystem not set to read-only, allowing modification.", "high", "static")
d("container-healthcheck", "Container Health Checks", "Container Security", "infra", 0.75, "Container Health", "Missing health checks preventing detection of compromised containers.", "medium", "static")
d("container-log-driver", "Container Logging", "Container Security", "infra", 0.75, "Container Log", "Container logs not forwarded to central logging or missing audit.", "medium", "static")
d("k8s-rbac", "Kubernetes RBAC Configuration", "Kubernetes Security", "infra", 0.9, "K8s RBAC", "Overly permissive ClusterRoleBindings or missing RBAC policies.", "critical", "static+dynamic")
d("k8s-network-policy", "Kubernetes Network Policies", "Kubernetes Security", "infra", 0.85, "K8s Network", "Missing network policies allowing unrestricted pod-to-pod communication.", "high", "static")
d("k8s-pod-security", "Kubernetes Pod Security", "Kubernetes Security", "infra", 0.9, "K8s Pod", "Pods running with privileged containers, host network, or host PID.", "critical", "static+dynamic")
d("k8s-secrets-management", "Kubernetes Secrets Management", "Kubernetes Security", "infra", 0.9, "K8s Secrets", "Secrets stored in plaintext in etcd or ConfigMaps.", "critical", "static")
d("k8s-service-account", "Kubernetes Service Account", "Kubernetes Security", "infra", 0.85, "K8s SA", "Default service account with automountServiceAccountToken enabled.", "high", "static")
d("k8s-image-pull-policy", "Kubernetes Image Pull Policy", "Kubernetes Security", "infra", 0.8, "K8s Image", "ImagePullPolicy: Always with untrusted registries or missing tag pinning.", "high", "static")
d("k8s-admission-control", "Kubernetes Admission Control", "Kubernetes Security", "infra", 0.85, "K8s Admission", "Missing PodSecurityPolicy or OPA Gatekeeper constraints.", "high", "static")
d("k8s-api-server", "Kubernetes API Server Security", "Kubernetes Security", "infra", 0.9, "K8s API", "API server with anonymous auth, weak TLS, or missing audit logging.", "critical", "static+dynamic")
d("k8s-etcd-security", "Kubernetes etcd Security", "Kubernetes Security", "infra", 0.9, "K8s etcd", "etcd without encryption at rest or client certificate authentication.", "critical", "static")
d("k8s-dashboard-exposure", "Kubernetes Dashboard Exposure", "Kubernetes Security", "infra", 0.85, "K8s Dashboard", "Kubernetes dashboard exposed without authentication or with admin privileges.", "high", "static+dynamic")
d("dockerfile-security", "Dockerfile Security", "Container Security", "infra", 0.85, "Dockerfile", "Insecure Dockerfile instructions (ADD from URL, running as root, no COPY --chown).", "high", "static")
d("docker-compose-security", "Docker Compose Security", "Container Security", "infra", 0.8, "Compose", "Docker Compose files with privileged containers or volume-mounted secrets.", "high", "static")
d("container-registry-security", "Container Registry Security", "Container Security", "infra", 0.85, "Registry", "Container registry with anonymous pull, weak authentication, or no vulnerability scanning.", "high", "static+dynamic")
# Database Security (15 domains)
d("database-sql-injection", "Database SQL Injection", "Database Security", "backend-api", 0.95, "DB SQL", "Direct SQL queries with string interpolation from user input.", "critical", "static+dynamic")
d("database-nosql-injection", "NoSQL Injection", "Database Security", "backend-api", 0.9, "DB NoSQL", "NoSQL queries with user-controlled operators or values.", "critical", "static+dynamic")
d("database-credential-exposure", "Database Credential Exposure", "Database Security", "infra", 0.9, "DB Creds", "Database credentials in source code, config files, or environment variables.", "critical", "static")
d("database-encryption-at-rest", "Database Encryption at Rest", "Database Security", "infra", 0.85, "DB Encrypt", "Database not encrypted at rest or using weak encryption.", "high", "static")
d("database-encryption-in-transit", "Database Encryption in Transit", "Database Security", "infra", 0.9, "DB TLS", "Database connections without TLS or with certificate verification disabled.", "critical", "static")
d("database-backup-security", "Database Backup Security", "Database Security", "infra", 0.85, "DB Backup", "Database backups stored unencrypted or without access controls.", "high", "static")
d("database-privilege-management", "Database Privilege Management", "Database Security", "infra", 0.9, "DB Priv", "Application using DBA/root account instead of least-privilege user.", "critical", "static")
d("database-audit-logging", "Database Audit Logging", "Database Security", "infra", 0.85, "DB Audit", "Missing query logging, connection auditing, or DDL change tracking.", "high", "static")
d("database-connection-pool", "Database Connection Pool Security", "Database Security", "infra", 0.8, "DB Pool", "Unbounded connection pools or missing connection timeout.", "high", "static")
d("database-stored-procedure", "Database Stored Procedure Security", "Database Security", "backend-api", 0.85, "DB SP", "Stored procedures with dynamic SQL or missing input validation.", "high", "static")
d("database-xss-in-output", "Database Output XSS", "Database Security", "frontend-web", 0.85, "DB XSS", "Data from database rendered without output encoding in web pages.", "high", "static")
d("database-data-masking", "Database Data Masking", "Database Security", "backend-api", 0.8, "DB Mask", "Sensitive data returned in API responses without masking.", "high", "static")
d("database-soft-delete", "Database Soft Delete Security", "Database Security", "backend-api", 0.75, "DB SoftDelete", "Soft-deleted records accessible through API or direct queries.", "medium", "static+dynamic")
d("database-row-level-security", "Database Row-Level Security", "Database Security", "backend-api", 0.85, "DB RowSec", "Missing row-level security allowing users to access other users' data.", "high", "static+dynamic")
d("database-query-optimization", "Database Query Security", "Database Security", "backend-api", 0.8, "DB Query", "Slow queries enabling timing attacks or resource exhaustion.", "high", "dynamic")
# Network Security (15 domains)
d("network-tls-configuration", "TLS Configuration", "Network Security", "infra", 0.9, "Net TLS", "Weak TLS versions (SSLv3, TLS 1.0, 1.1) or cipher suites.", "critical", "static+dynamic")
d("network-dns-security", "DNS Security", "Network Security", "infra", 0.85, "Net DNS", "DNS rebinding, DNS over plain UDP, or missing DNSSEC.", "high", "static+dynamic")
d("network-http-headers", "HTTP Security Headers", "Network Security", "infra", 0.85, "Net Headers", "Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options headers.", "high", "static")
d("network-cors-configuration", "CORS Configuration", "Network Security", "infra", 0.85, "Net CORS", "Permissive CORS allowing any origin with credentials.", "high", "static")
d("network-certificate-validation", "Certificate Validation", "Network Security", "infra", 0.9, "Net Cert", "Missing or disabled SSL/TLS certificate verification.", "critical", "static+dynamic")
d("network-port-exposure", "Port Exposure", "Network Security", "infra", 0.8, "Net Ports", "Unnecessary ports open to the network.", "high", "static+dynamic")
d("network-proxy-security", "Proxy Security", "Network Security", "infra", 0.85, "Net Proxy", "Proxy server with weak authentication or forwarding internal headers.", "high", "static+dynamic")
d("network-firewall-rules", "Firewall Rules", "Network Security", "infra", 0.85, "Net Firewall", "Overly permissive firewall rules or missing ingress/egress filtering.", "high", "static+dynamic")
d("network-waf-bypass", "WAF Bypass", "Network Security", "infra", 0.8, "Net WAF", "WAF evasion techniques or incomplete rule coverage.", "high", "dynamic")
d("network-rate-limiting", "Rate Limiting", "Network Security", "infra", 0.85, "Net RateLimit", "Missing or ineffective rate limiting on API endpoints.", "high", "dynamic")
d("network-ddos-protection", "DDoS Protection", "Network Security", "infra", 0.8, "Net DDoS", "Missing DDoS mitigation or CDN-level protection.", "high", "dynamic")
d("network-packet-filtering", "Packet Filtering", "Network Security", "infra", 0.8, "Net Packet", "Insufficient packet inspection or missing IPS rules.", "high", "static+dynamic")
d("network-vpn-security", "VPN Security", "Network Security", "infra", 0.85, "Net VPN", "Weak VPN authentication, split tunneling, or outdated protocols.", "high", "static+dynamic")
d("network-load-balancer", "Load Balancer Security", "Network Security", "infra", 0.85, "Net LB", "Load balancer with weak health checks or missing SSL termination.", "high", "static")
d("network-api-gateway-security", "API Gateway Security", "Network Security", "infra", 0.85, "Net APIGW", "Missing request validation, authentication, or throttling at gateway.", "high", "static+dynamic")
# Email Security (8 domains)
d("email-spoofing", "Email Spoofing", "Email Security", "infra", 0.85, "Email Spoof", "Missing SPF, DKIM, or DMARC records allowing email spoofing.", "high", "static+dynamic")
d("email-phishing", "Phishing Protection", "Email Security", "infra", 0.8, "Email Phish", "Missing anti-phishing controls or user awareness training.", "high", "manual-review")
d("email-attachment-security", "Email Attachment Security", "Email Security", "infra", 0.85, "Email Attach", "Unfiltered email attachments allowing malware delivery.", "high", "static+dynamic")
d("email-encryption", "Email Encryption", "Email Security", "infra", 0.8, "Email Encrypt", "Email transmitted without TLS or S/MIME/PGP encryption.", "high", "static")
d("email-link-validation", "Email Link Validation", "Email Security", "backend-api", 0.8, "Email Link", "Email links with unvalidated redirects or tracking parameters.", "high", "static+dynamic")
d("email-unsubscribe-security", "Unsubscribe Security", "Email Security", "backend-api", 0.75, "Email Unsub", "Unsubscribe links without CSRF protection or abuse potential.", "medium", "static+dynamic")
d("email-bounce-security", "Email Bounce Handling", "Email Security", "infra", 0.7, "Email Bounce", "Email bounce messages leaking user existence or internal information.", "medium", "static")
d("email-list-security", "Mailing List Security", "Email Security", "infra", 0.75, "Email List", "Mailing lists exposing subscriber addresses or allowing unauthorized posting.", "medium", "static+dynamic")
# Fraud & Abuse (10 domains)
d("fraud-account-takeover", "Account Takeover", "Fraud Prevention", "backend-api", 0.9, "Fraud ATO", "Credential stuffing, brute force, or session hijacking leading to account compromise.", "critical", "dynamic")
d("fraud-bot-detection", "Bot Detection", "Fraud Prevention", "backend-api", 0.85, "Fraud Bot", "Missing bot detection allowing automated abuse of forms and APIs.", "high", "dynamic")
d("fraud-payment-abuse", "Payment Fraud", "Fraud Prevention", "backend-api", 0.9, "Fraud Payment", "Credit card testing, refund abuse, or subscription manipulation.", "critical", "dynamic")
d("fraud-coupon-abuse", "Coupon/Promo Abuse", "Fraud Prevention", "backend-api", 0.8, "Fraud Coupon", "Stacking, sharing, or automating coupon codes beyond intended use.", "high", "dynamic")
d("fraud-referral-abuse", "Referral Program Abuse", "Fraud Prevention", "backend-api", 0.8, "Fraud Referral", "Self-referral, multi-accounting, or automated referral farming.", "high", "dynamic")
d("fraud-content-spam", "Content Spam", "Fraud Prevention", "backend-api", 0.8, "Fraud Spam", "Automated posting of spam content, links, or advertisements.", "high", "dynamic")
d("fraud-web-scraping", "Web Scraping", "Fraud Prevention", "backend-api", 0.8, "Fraud Scrape", "Automated data extraction bypassing rate limits or access controls.", "high", "dynamic")
d("fraud-click-fraud", "Click Fraud", "Fraud Prevention", "backend-api", 0.75, "Fraud Click", "Automated clicking on ads, buttons, or links for financial gain.", "medium", "dynamic")
d("fraud-identity-theft", "Identity Theft Prevention", "Fraud Prevention", "backend-api", 0.85, "Fraud ID", "Insufficient identity verification allowing impersonation.", "high", "static+dynamic")
d("fraud-api-abuse", "API Abuse", "Fraud Prevention", "backend-api", 0.85, "Fraud API", "Automated API abuse for data harvesting, account creation, or service abuse.", "high", "dynamic")
# Business Logic (10 domains)
d("blogic-privilege-escalation", "Business Logic Privilege Escalation", "Business Logic", "backend-api", 0.9, "BLogic Priv", "Manipulating business logic to gain unauthorized access or privileges.", "critical", "static+dynamic")
d("blogic-price-manipulation", "Price Manipulation", "Business Logic", "backend-api", 0.9, "BLogic Price", "Modifying prices, quantities, or discounts in client-side requests.", "critical", "dynamic")
d("blogic-race-condition", "Business Logic Race Condition", "Business Logic", "backend-api", 0.85, "BLogic Race", "Concurrent requests exploiting time-of-check-to-time-of-use gaps.", "high", "dynamic")
d("blogic-workflow-bypass", "Workflow Bypass", "Business Logic", "backend-api", 0.85, "BLogic Workflow", "Skipping steps in multi-step processes (checkout, registration).", "high", "static+dynamic")
d("blogic-amount-tampering", "Amount/Quantity Tampering", "Business Logic", "backend-api", 0.9, "BLogic Amount", "Negative quantities, zero prices, or overflow amounts in transactions.", "critical", "dynamic")
d("blogic-state-confusion", "State Confusion", "Business Logic", "backend-api", 0.85, "BLogic State", "Operating on resources in unexpected states (expired, cancelled, completed).", "high", "static+dynamic")
d("blogic-resource-exhaustion", "Resource Exhaustion", "Business Logic", "backend-api", 0.8, "BLogic Resource", "Abusing business operations to consume excessive resources.", "high", "dynamic")
d("blogic-logic-bomb", "Logic Bomb", "Business Logic", "backend-api", 0.8, "BLogic Bomb", "Hidden conditions that trigger malicious behavior under specific circumstances.", "high", "static")
d("blogic-time-of-check", "Time-of-Check to Time-of-Use", "Business Logic", "backend-api", 0.85, "BLogic TOCTOU", "Resource state changes between validation and usage.", "high", "static+dynamic")
d("blogic-insufficient-validation", "Insufficient Business Validation", "Business Logic", "backend-api", 0.85, "BLogic Validate", "Missing server-side validation of business rules and constraints.", "high", "static+dynamic")
# Crypto Implementation (15 domains)
d("crypto-weak-hashing", "Weak Hashing Algorithms", "Cryptography Implementation", "backend-api", 0.9, "Crypto Hash", "Use of MD5, SHA1, or other broken hash algorithms for security purposes.", "critical", "static")
d("crypto-hardcoded-key", "Hardcoded Cryptographic Keys", "Cryptography Implementation", "backend-api", 0.95, "Crypto Key", "Encryption keys or secrets hardcoded in source code.", "critical", "static")
d("crypto-weak-random", "Weak Random Number Generation", "Cryptography Implementation", "backend-api", 0.85, "Crypto Random", "Use of Math.random(), random(), or other non-cryptographic RNG for security.", "high", "static")
d("crypto-iv-reuse", "IV/Nonce Reuse", "Cryptography Implementation", "backend-api", 0.9, "Crypto IV", "Reusing initialization vectors or nonces in encryption.", "critical", "static")
d("crypto-padding-oracle", "Padding Oracle", "Cryptography Implementation", "backend-api", 0.85, "Crypto Padding", "Different error messages for invalid padding enabling padding oracle attacks.", "high", "static+dynamic")
d("crypto-timing-attack", "Timing Attack on Crypto", "Cryptography Implementation", "backend-api", 0.8, "Crypto Timing", "Non-constant-time comparison of cryptographic values.", "high", "static")
d("crypto-key-length", "Insufficient Key Length", "Cryptography Implementation", "backend-api", 0.85, "Crypto Length", "RSA keys < 2048-bit, AES keys < 128-bit, or other insufficient key sizes.", "high", "static")
d("crypto-certificate-validation", "Certificate Validation", "Cryptography Implementation", "backend-api", 0.9, "Crypto Cert", "Missing or disabled TLS certificate validation.", "critical", "static+dynamic")
d("crypto-weak-cipher", "Weak Cipher Suites", "Cryptography Implementation", "infra", 0.85, "Crypto Cipher", "Use of DES, RC4, 3DES, or export cipher suites.", "high", "static+dynamic")
d("crypto-ecb-mode", "ECB Mode Usage", "Cryptography Implementation", "backend-api", 0.85, "Crypto ECB", "Using ECB mode for symmetric encryption leaking patterns.", "high", "static")
d("crypto-key-derivation", "Weak Key Derivation", "Cryptography Implementation", "backend-api", 0.85, "Crypto KDF", "Insufficient iterations in PBKDF2, bcrypt, or argon2.", "high", "static")
d("crypto-rsa-padding", "RSA Padding", "Cryptography Implementation", "backend-api", 0.85, "Crypto RSA", "RSA with PKCS#1 v1.5 padding instead of OAEP.", "high", "static")
d("crypto-hmac-validation", "HMAC Validation", "Cryptography Implementation", "backend-api", 0.85, "Crypto HMAC", "HMAC comparison using non-constant-time function.", "high", "static")
d("crypto-seed-entropy", "Insufficient Seed Entropy", "Cryptography Implementation", "backend-api", 0.8, "Crypto Seed", "Random number generators seeded with predictable values.", "high", "static")
d("crypto-deprecated-algorithms", "Deprecated Algorithms", "Cryptography Implementation", "backend-api", 0.85, "Crypto Deprecated", "Use of deprecated algorithms like SHA-1 for signatures or MD5 for passwords.", "high", "static")
# Mobile Security (15 domains)
d("mobile-insecure-storage", "Insecure Local Storage", "Mobile Security", "mobile-native", 0.9, "Mobile Storage", "Sensitive data in SharedPreferences, UserDefaults, or AsyncStorage without encryption.", "critical", "static")
d("mobile-certificate-pinning", "Certificate Pinning", "Mobile Security", "mobile-native", 0.85, "Mobile Pin", "Missing or bypassable TLS certificate pinning.", "high", "static+dynamic")
d("mobile-biometric-auth", "Biometric Authentication Bypass", "Mobile Security", "mobile-native", 0.85, "Mobile Bio", "Biometric auth fallback to weak PIN or no auth.", "high", "static+dynamic")
d("mobile-code-obfuscation", "Code Obfuscation", "Mobile Security", "mobile-native", 0.8, "Mobile Obfusc", "App binary without ProGuard, R8, or Swift obfuscation.", "high", "static")
d("mobile-jailbreak-detection", "Jailbreak/Root Detection", "Mobile Security", "mobile-native", 0.75, "Mobile Root", "Missing jailbreak or root detection allowing modified runtime.", "medium", "static+dynamic")
d("mobile-deep-link-security", "Deep Link Security", "Mobile Security", "mobile-native", 0.85, "Mobile DeepLink", "Universal links or custom URL schemes without proper validation.", "high", "static+dynamic")
d("mobile-intent-security", "Intent Security (Android)", "Mobile Security", "mobile-native", 0.85, "Mobile Intent", "Exported components with intent filters allowing unauthorized access.", "high", "static")
d("mobile-keychain-security", "Keychain/Keystore Security", "Mobile Security", "mobile-native", 0.9, "Mobile Keychain", "Sensitive data stored in insecure keychain accessibility levels.", "critical", "static")
d("mobile-screen-capture", "Screen Capture Prevention", "Mobile Security", "mobile-native", 0.75, "Mobile Screen", "Screen recording or screenshot capturing sensitive content.", "medium", "static")
d("mobile-pasteboard-security", "Pasteboard Security", "Mobile Security", "mobile-native", 0.8, "Mobile Paste", "Sensitive data copied to system clipboard accessible by other apps.", "high", "static")
d("mobile-webview-security", "WebView Security", "Mobile Security", "mobile-native", 0.85, "Mobile WebView", "WebView with JavaScript enabled or file access from untrusted content.", "high", "static")
d("mobile-backup-security", "Mobile Backup Security", "Mobile Security", "mobile-native", 0.85, "Mobile Backup", "App data included in cloud backups without user awareness.", "high", "static")
d("mobile-logging-security", "Mobile Logging Security", "Mobile Security", "mobile-native", 0.8, "Mobile Log", "Sensitive data in iOS NSLog, Android Logcat, or crash reports.", "high", "static")
d("mobile-permission-request", "Permission Request Security", "Mobile Security", "mobile-native", 0.8, "Mobile Perm", "Requesting excessive or unnecessary device permissions.", "high", "static")
d("mobile-update-mechanism", "App Update Mechanism", "Mobile Security", "mobile-native", 0.8, "Mobile Update", "Insecure update mechanism allowing code injection or tampering.", "high", "static+dynamic")
# Security Headers (10 domains)
d("header-csp", "Content Security Policy", "HTTP Security Headers", "infra", 0.9, "Header CSP", "Missing or weak Content-Security-Policy header allowing XSS.", "critical", "static")
d("header-hsts", "HTTP Strict Transport Security", "HTTP Security Headers", "infra", 0.85, "Header HSTS", "Missing or short HSTS max-age allowing protocol downgrade.", "high", "static")
d("header-xfo", "X-Frame-Options", "HTTP Security Headers", "infra", 0.8, "Header XFO", "Missing X-Frame-Options allowing clickjacking.", "high", "static")
d("header-xcto", "X-Content-Type-Options", "HTTP Security Headers", "infra", 0.8, "Header XCTO", "Missing X-Content-Type-Options: nosniff allowing MIME confusion.", "high", "static")
d("header-permissions-policy", "Permissions Policy", "HTTP Security Headers", "infra", 0.8, "Header PP", "Missing Permissions-Policy allowing browser feature abuse.", "high", "static")
d("header-referrer-policy", "Referrer Policy", "HTTP Security Headers", "infra", 0.75, "Header RP", "Missing or overly permissive Referrer-Policy leaking sensitive URLs.", "medium", "static")
d("header-x-xss-protection", "X-XSS-Protection", "HTTP Security Headers", "infra", 0.75, "Header XXSS", "Missing or deprecated X-XSS-Protection header.", "medium", "static")
d("header-cross-origin", "Cross-Origin Policies", "HTTP Security Headers", "infra", 0.85, "Header COEP", "Missing COOP/COEP/CORP headers enabling Spectre-type attacks.", "high", "static")
d("header-cache-control", "Cache Control Security", "HTTP Security Headers", "infra", 0.8, "Header CC", "Missing Cache-Control headers allowing sensitive data caching.", "high", "static")
d("header-feature-policy", "Feature Policy / Permissions Policy", "HTTP Security Headers", "infra", 0.75, "Header FP", "Missing Feature-Policy controlling access to browser APIs.", "medium", "static")
# Privacy (10 domains)
d("privacy-cookie-consent", "Cookie Consent", "Privacy Engineering", "frontend-web", 0.8, "Privacy Cookie", "Cookies set before user consent or missing consent mechanism.", "high", "static+dynamic")
d("privacy-data-collection", "Data Collection Minimization", "Privacy Engineering", "backend-api", 0.8, "Privacy Collect", "Collecting more personal data than necessary for the stated purpose.", "high", "static")
d("privacy-data-retention", "Data Retention Limits", "Privacy Engineering", "backend-api", 0.8, "Privacy Retain", "No defined data retention period or automatic deletion mechanism.", "high", "static+manual-review")
d("privacy-cross-site-tracking", "Cross-Site Tracking", "Privacy Engineering", "frontend-web", 0.85, "Privacy Track", "Third-party scripts tracking users across domains without consent.", "high", "static+dynamic")
d("privacy-fingerprinting", "Browser Fingerprinting", "Privacy Engineering", "frontend-web", 0.8, "Privacy FP", "Canvas, WebGL, or Audio fingerprinting collecting device identifiers.", "high", "static+dynamic")
d("privacy-analytics-consent", "Analytics Consent", "Privacy Engineering", "frontend-web", 0.8, "Privacy Analytics", "Analytics scripts loading without user consent.", "high", "static+dynamic")
d("privacy-data-breach-detection", "Data Breach Detection", "Privacy Engineering", "infra", 0.85, "Privacy Breach", "Missing monitoring for unauthorized data access or exfiltration.", "high", "static+dynamic")
d("privacy-privacy-by-design", "Privacy by Design", "Privacy Engineering", "backend-api", 0.8, "Privacy Design", "Privacy considerations not embedded in system design.", "high", "manual-review")
d("privacy-data-anonymization", "Data Anonymization", "Privacy Engineering", "backend-api", 0.8, "Privacy Anon", "Personal data not properly anonymized or pseudonymized.", "high", "static")
d("privacy-consent-management", "Consent Management Platform", "Privacy Engineering", "frontend-web", 0.85, "Privacy CMP", "Missing or non-compliant consent management for GDPR/CCPA.", "high", "static+dynamic")
# Incident Response (5 domains)
d("incident-response-plan", "Incident Response Plan", "Incident Response", "infra", 0.85, "IR Plan", "Documented incident response procedures and escalation paths.", "high", "manual-review")
d("incident-detection", "Incident Detection", "Incident Response", "infra", 0.9, "IR Detect", "Monitoring and alerting systems for security event detection.", "critical", "static+dynamic")
d("incident-containment", "Incident Containment", "Incident Response", "infra", 0.85, "IR Contain", "Procedures to contain active security incidents.", "high", "manual-review")
d("incident-forensics", "Incident Forensics", "Incident Response", "infra", 0.8, "IR Forensics", "Forensic evidence collection and preservation procedures.", "high", "manual-review")
d("incident-recovery", "Incident Recovery", "Incident Response", "infra", 0.8, "IR Recover", "Recovery procedures and post-incident review processes.", "high", "manual-review")
# Threat Modeling (5 domains)
d("threat-model-stride", "STRIDE Threat Modeling", "Threat Modeling", "backend-api", 0.85, "Threat STRIDE", "Systematic threat analysis using Spoofing, Tampering, Repudiation, Information Disclosure, DoS, and Elevation of Privilege.", "high", "manual-review")
d("threat-model-attack-surface", "Attack Surface Analysis", "Threat Modeling", "backend-api", 0.85, "Threat Surface", "Identification and reduction of attack surface across all entry points.", "high", "static+manual-review")
d("threat-model-abuse-case", "Abuse Case Development", "Threat Modeling", "backend-api", 0.8, "Threat Abuse", "Documented abuse cases and misuse scenarios for critical features.", "high", "manual-review")
d("threat-model-risk-assessment", "Risk Assessment", "Threat Modeling", "infra", 0.85, "Threat Risk", "Risk scoring and prioritization of identified vulnerabilities.", "high", "manual-review")
d("threat-model-mitigation", "Threat Mitigation Tracking", "Threat Modeling", "infra", 0.8, "Threat Mitigate", "Tracking and verification of threat mitigations through implementation.", "high", "manual-review")


# ══════════════════════════════════════════════════════════════════════════════
# ── Additional Specialized Domains (45 more to reach 800) ────────────────────
# API Design & Architecture
d("api-versioning-security", "API Versioning Security", "API Design Security", "backend-api", 0.8, "API Version", "Old API versions exposed without deprecation or access controls.", "high", "static")
d("api-rate-limiting", "API Rate Limiting Architecture", "API Design Security", "backend-api", 0.85, "API Rate", "Missing or inconsistent rate limiting across API endpoints.", "high", "dynamic")
d("api-content-negotiation", "API Content Negotiation", "API Design Security", "backend-api", 0.75, "API Content", "Content-type validation missing, allowing MIME confusion attacks.", "medium", "static")
d("api-pagination-security", "API Pagination Security", "API Design Security", "backend-api", 0.8, "API Page", "Unbounded pagination allowing resource exhaustion.", "high", "dynamic")
d("api-error-format", "API Error Format Security", "API Design Security", "backend-api", 0.8, "API Error", "API error responses leaking internal implementation details.", "high", "static")
d("api-idempotency", "API Idempotency", "API Design Security", "backend-api", 0.8, "API Idemp", "Missing idempotency keys allowing duplicate operations on retry.", "high", "static")
d("api-hateoas-leak", "API HATEOAS Information Leak", "API Design Security", "backend-api", 0.75, "API HATEOAS", "Hypermedia links exposing internal endpoints or admin routes.", "medium", "static+dynamic")
# WebAssembly & Browser Security
d("wasm-sandbox-escape", "WASM Sandbox Escape", "WASM Security", "frontend-web", 0.85, "WASM Escape", "WebAssembly module breaking out of sandbox via host function abuse.", "high", "static")
d("wasm-data-leakage", "WASM Data Leakage", "WASM Security", "frontend-web", 0.8, "WASM Leak", "Sensitive data accessible through WASM linear memory.", "high", "static")
d("wasm-untrusted-code", "WASM Untrusted Code Execution", "WASM Security", "frontend-web", 0.85, "WASM Untrusted", "Loading and executing untrusted WASM modules without validation.", "high", "static+dynamic")
d("wasm-gc-exploitation", "WASM GC Exploitation", "WASM Security", "frontend-web", 0.8, "WASM GC", "Exploiting garbage collector behavior in WASM for memory corruption.", "high", "static")
# Modern Framework Security
d("remix-loader-injection", "Remix Loader Injection", "Remix Security", "backend-api", 0.85, "Remix Loader", "Unvalidated data in Remix loaders leading to injection.", "high", "static")
d("remix-action-csrf", "Remix Action CSRF", "Remix Security", "backend-api", 0.8, "Remix CSRF", "Missing CSRF protection on Remix form actions.", "high", "static+dynamic")
d("astro-islands-security", "Astro Islands Security", "Astro Security", "frontend-web", 0.75, "Astro Islands", "Interactive islands with unsanitized data in static pages.", "medium", "static")
d("qwik-hydration-security", "Qwik Hydration Security", "Qwik Security", "frontend-web", 0.8, "Qwik Hydrate", "Server-side state leaked during Qwik hydration.", "high", "static")
d("solidjs-reactivity-security", "SolidJS Reactive Data Security", "SolidJS Security", "frontend-web", 0.75, "SolidJS Reactive", "Reactive signals exposing sensitive state in browser.", "medium", "static")
# Infrastructure as Code
d("terraform-state-exposure", "Terraform State File Exposure", "IaC Security", "infra", 0.9, "TF State", "Terraform state files with secrets stored unencrypted or in public buckets.", "critical", "static")
d("terraform-provider-security", "Terraform Provider Security", "IaC Security", "infra", 0.85, "TF Provider", "Using unverified or malicious Terraform providers.", "high", "static")
d("terraform-module-source", "Terraform Module Source Security", "IaC Security", "infra", 0.85, "TF Module", "Modules sourced from untrusted registries or Git URLs without pinning.", "high", "static")
d("ansible-vault-security", "Ansible Vault Security", "IaC Security", "infra", 0.8, "Ansible Vault", "Ansible vault passwords in plaintext or weak encryption.", "high", "static")
d("pulumi-secret-management", "Pulumi Secret Management", "IaC Security", "infra", 0.8, "Pulumi Secret", "Secrets stored in Pulumi state without encryption.", "high", "static")
d("cloudformation-security", "CloudFormation Security", "IaC Security", "cloud-aws", 0.85, "CFN Security", "CloudFormation templates with overly permissive IAM roles.", "high", "static")
d("helm-chart-security", "Helm Chart Security", "IaC Security", "infra", 0.85, "Helm Security", "Helm charts with privileged containers or default credentials.", "high", "static")
d("crossplane-security", "Crossplane Provider Security", "IaC Security", "infra", 0.8, "Crossplane", "Crossplane compositions with excessive provider permissions.", "high", "static")
# Data Engineering Security
d("spark-data-exposure", "Apache Spark Data Exposure", "Data Engineering Security", "infra", 0.8, "Spark Data", "Spark UI or data frames exposed without authentication.", "high", "static+dynamic")
d("kafka-topic-acl", "Kafka Topic ACL", "Data Engineering Security", "infra", 0.8, "Kafka ACL", "Kafka topics without access control allowing unauthorized consumption.", "high", "static")
d("airflow-dag-security", "Airflow DAG Security", "Data Engineering Security", "infra", 0.8, "Airflow DAG", "Airflow DAGs with hardcoded connections or weak XCom security.", "high", "static")
d("dbt-model-security", "dbt Model Security", "Data Engineering Security", "infra", 0.75, "dbt Model", "dbt models with SQL injection via Jinja templates.", "medium", "static")
d("snowflake-security", "Snowflake Security", "Data Engineering Security", "cloud-aws", 0.85, "Snowflake", "Snowflake with weak authentication or over-privileged roles.", "high", "static+dynamic")
d("bigquery-authorized-datasets", "BigQuery Authorized Datasets", "Data Engineering Security", "cloud-gcp", 0.8, "BQ Auth", "BigQuery datasets shared via authorized views without access controls.", "high", "static")
d("redshift-security", "Redshift Security", "Data Engineering Security", "cloud-aws", 0.85, "Redshift", "Redshift cluster with public accessibility or weak encryption.", "high", "static+dynamic")
d("databricks-security", "Databricks Security", "Data Engineering Security", "cloud-aws", 0.85, "Databricks", "Databricks notebooks with stored credentials or overly permissive clusters.", "high", "static")
# Game Security
d("game-client-trust", "Game Client Trust", "Game Security", "frontend-web", 0.85, "Game Client", "Client-side game logic validated server-side allowing speed hacks.", "high", "static+dynamic")
d("game-memory-corruption", "Game Memory Corruption", "Game Security", "native-code", 0.9, "Game Memory", "Buffer overflows in game networking or rendering code.", "critical", "static")
d("game-cheat-detection", "Game Cheat Detection", "Game Security", "frontend-web", 0.8, "Game Cheat", "Missing server-side validation of game state changes.", "high", "static+dynamic")
d("game-item-duplication", "Game Item Duplication", "Game Security", "backend-api", 0.85, "Game Dup", "Race conditions allowing item or currency duplication.", "high", "dynamic")
# Blockchain & Web3
d("web3-smart-contract", "Smart Contract Vulnerability", "Web3 Security", "backend-api", 0.9, "Web3 Contract", "Reentrancy, overflow, or access control bugs in smart contracts.", "critical", "static")
d("web3-private-key", "Private Key Exposure", "Web3 Security", "backend-api", 0.95, "Web3 Key", "Private keys or seeds stored in plaintext in source code.", "critical", "static")
d("web3-oracle-manipulation", "Oracle Manipulation", "Web3 Security", "backend-api", 0.85, "Web3 Oracle", "Price oracle manipulation leading to flash loan attacks.", "high", "dynamic")
d("web3-front-running", "Front-Running", "Web3 Security", "backend-api", 0.8, "Web3 FrontRun", "Transaction ordering allowing MEV extraction.", "high", "dynamic")
d("web3-governance-attack", "Governance Attack", "Web3 Security", "backend-api", 0.85, "Web3 Gov", "Flash loan governance attacks or vote buying.", "high", "dynamic")
# Final 4 to reach 800
d("quantum-safe-crypto", "Quantum-Safe Cryptography", "Post-Quantum Security", "backend-api", 0.85, "PQC", "Use of algorithms vulnerable to quantum computing attacks (RSA, ECC, DH).", "high", "static")
d("supply-chain-sig-verify", "Artifact Signature Verification", "Supply Chain Integrity", "infra", 0.9, "Sig Verify", "Build artifacts not cryptographically signed or verified before deployment.", "critical", "static")
d("zero-trust-architecture", "Zero Trust Architecture", "Network Security", "infra", 0.9, "ZTA", "Implicit trust in network location instead of verifying every request.", "critical", "static+manual-review")
d("devsecops-secret-scanning", "Pre-Commit Secret Scanning", "DevSecOps", "infra", 0.85, "DSScan", "Missing pre-commit hooks for secret detection allowing credentials in repos.", "high", "static")

# YAML GENERATION
# ══════════════════════════════════════════════════════════════════════════════

def _gen_activation_signals(did, ctype, source, name):
    """Generate meaningful activation signals based on domain characteristics."""
    signals = []
    excluded = []

    # Component-type based signals
    ctype_map = {
        'backend-api': ['route_handler_detected', 'api_endpoint_present', 'server_side_code_detected'],
        'frontend-web': ['javascript_file_detected', 'html_template_detected', 'css_file_detected'],
        'infra': ['config_file_detected', 'docker_file_detected', 'yaml_manifest_detected'],
        'mobile-native': ['mobile_project_detected', 'ios_swift_detected', 'android_kotlin_detected'],
        'native-code': ['c_cpp_source_detected', 'rust_source_detected', 'memory_management_detected'],
        'cloud-aws': ['aws_sdk_detected', 'terraform_aws_detected', 'cloudformation_detected'],
        'cloud-azure': ['azure_sdk_detected', 'terraform_azure_detected', 'arm_template_detected'],
        'cloud-gcp': ['gcp_sdk_detected', 'terraform_gcp_detected', 'gcloud_config_detected'],
        'iot-device': ['iot_protocol_detected', 'mqtt_handler_detected', 'embedded_code_detected'],
        'ai-ml': ['ml_framework_detected', 'model_file_detected', 'training_code_detected'],
        'desktop-app': ['electron_detected', 'tauri_detected', 'desktop_framework_detected'],
    }
    base_signals = ctype_map.get(ctype.split(',')[0].strip(), ['code_detected'])
    signals.extend(base_signals)

    # Technology-specific signals from domain_id
    tech_patterns = {
        'django': ['django_project_detected'], 'flask': ['flask_app_detected'],
        'express': ['express_app_detected'], 'spring': ['spring_project_detected'],
        'rails': ['rails_project_detected'], 'laravel': ['laravel_project_detected'],
        'nextjs': ['nextjs_project_detected'], 'nuxt': ['nuxt_project_detected'],
        'react': ['react_component_detected'], 'vue': ['vue_component_detected'],
        'angular': ['angular_component_detected'], 'svelte': ['svelte_component_detected'],
        'graphql': ['graphql_schema_detected'], 'grpc': ['grpc_proto_detected'],
        'docker': ['dockerfile_detected'], 'kubernetes': ['k8s_manifest_detected'],
        'terraform': ['terraform_file_detected'], 'ansible': ['ansible_playbook_detected'],
        'helm': ['helm_chart_detected'], 'aws': ['aws_resource_detected'],
        'azure': ['azure_resource_detected'], 'gcp': ['gcp_resource_detected'],
        'kafka': ['kafka_config_detected'], 'redis': ['redis_config_detected'],
        'mysql': ['mysql_config_detected'], 'postgresql': ['postgres_config_detected'],
        'mongodb': ['mongodb_config_detected'], 'elasticsearch': ['elastic_config_detected'],
        'rabbitmq': ['rabbitmq_config_detected'], 'consul': ['consul_config_detected'],
        'vault': ['vault_config_detected'], 'nginx': ['nginx_config_detected'],
        'apache': ['apache_config_detected'], 'tomcat': ['tomcat_config_detected'],
        'iis': ['iis_config_detected'], 'haproxy': ['haproxy_config_detected'],
        'wordpress': ['wordpress_detected'], 'drupal': ['drupal_detected'],
        'electron': ['electron_main_detected'], 'tauri': ['tauri_config_detected'],
        'webassembly': ['wasm_module_detected'], 'remix': ['remix_route_detected'],
        'astro': ['astro_component_detected'], 'qwik': ['qwik_component_detected'],
        'fastapi': ['fastapi_app_detected'], 'go': ['go_source_detected'],
        'rust': ['rust_source_detected'], 'java': ['java_source_detected'],
        'php': ['php_source_detected'], 'ruby': ['ruby_source_detected'],
        'c_cpp': ['c_cpp_source_detected'], 'typescript': ['typescript_source_detected'],
    }
    for key, pats in tech_patterns.items():
        if key in did.lower():
            signals.extend(pats)
            break

    # OWASP/framework-specific signals
    if 'owasp' in did or 'asvs' in did:
        signals.append('web_application_detected')
    if 'cwe' in did:
        signals.append('code_vulnerability_pattern_present')
    if 'nist' in did:
        signals.append('enterprise_system_detected')
    if 'mitre' in did:
        signals.append('attack_technique_relevant')
    if 'cis' in did:
        signals.append('system_configuration_present')
    if 'pci' in did:
        signals.append('payment_data_processed')
    if 'hipaa' in did:
        signals.append('health_data_processed')
    if 'gdpr' in did:
        signals.append('personal_data_processed')
    if 'soc2' in did:
        signals.append('enterprise_compliance_required')
    if 'iso27001' in did:
        signals.append('isms_framework_active')
    if 'supply-chain' in did or 'supply' in did:
        signals.append('dependency_management_detected')
    if 'secrets' in did:
        signals.append('secret_management_present')
    if 'incident' in did:
        signals.append('security_monitoring_active')
    if 'threat' in did:
        signals.append('threat_modeling_active')

    # Ensure at least 3 signals
    if len(signals) < 3:
        signals.append('code_in_scope')

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for s in signals:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    excluded.append(f'no_relevant_code_for_{ctype.split(",")[0].strip()}')

    return unique[:5], excluded  # max 5 signals per domain


_seen_names = set()

def generate_domain_yaml(did, name, source, ctype, weight, clause, desc, sev, check):
    prefix = did.upper().replace("-", "")[:8]
    # Auto-prefix source context to make display names unique
    if name in _seen_names:
        short_src = source.split('(')[0].split(':')[0].strip()
        if len(short_src) > 20:
            short_src = short_src[:20]
        display = f"{name} ({short_src})"
    else:
        display = name
    _seen_names.add(name)
    req_sigs, excl_sigs = _gen_activation_signals(did, ctype, source, name)
    req_yaml = '\n'.join(f'    - signal: "{s}"' for s in req_sigs)
    excl_yaml = '\n'.join(f'    - signal: "{s}"' for s in excl_sigs)
    return f"""# Patchi Security Domain: {did}
# Source: {source}
# Auto-generated — curated from {source}

domain_id: "{did}"
version: "1.0.0"
display_name: "{display}"
source_standard: "{source}"
component_type: "{ctype}"
weight: {weight}

activation_signals:
  required_any:
{req_yaml}
  excluded_if:
{excl_yaml}

controls:
  - control_id: "{prefix}-01"
    name: "{name} — Primary Control"
    description: "{desc}"
    source_clause: "{clause}"
    severity: "{sev}"
    check_method: "{check}"
    detector: "static analysis + semantic pattern matching"
    remediation_ref: "fix-playbook://{prefix}-01"

  - control_id: "{prefix}-02"
    name: "{name} — Input Validation"
    description: "Validate and sanitize all inputs related to {name.lower()}"
    source_clause: "{clause}"
    severity: "{sev}"
    check_method: "{check}"
    detector: "input validation pattern analysis"
    remediation_ref: "fix-playbook://{prefix}-02"

  - control_id: "{prefix}-03"
    name: "{name} — Configuration Hardening"
    description: "Apply secure configuration defaults for {name.lower()}"
    source_clause: "{clause}"
    severity: "medium"
    check_method: "static"
    detector: "configuration analysis"
    remediation_ref: "fix-playbook://{prefix}-03"

  - control_id: "{prefix}-04"
    name: "{name} — Monitoring and Logging"
    description: "Log and monitor all {name.lower()} events for audit and detection"
    source_clause: "{clause}"
    severity: "medium"
    check_method: "static"
    detector: "logging pattern analysis"
    remediation_ref: "fix-playbook://{prefix}-04"

  - control_id: "{prefix}-05"
    name: "{name} — Error Handling"
    description: "Handle {name.lower()} errors securely without information leakage"
    source_clause: "{clause}"
    severity: "medium"
    check_method: "{check}"
    detector: "error handling pattern analysis"
    remediation_ref: "fix-playbook://{prefix}-05"
"""


def generate_playbook_yaml(did, name, source, sev):
    prefix = did.upper().replace("-", "")[:8]
    controls = []
    for i in range(1, 6):
        cid = f"{prefix}-{i:02d}"
        names = [
            f"Primary {name} Control",
            f"Input Validation for {name}",
            f"Configuration Hardening for {name}",
            f"Monitoring and Logging for {name}",
            f"Error Handling for {name}",
        ]
        tools = ["semgrep", "bandit", "ruff", "semgrep", "semgrep"]
        entry = (
            f'- control_id: "{cid}"\n'
            f'  playbook_version: "1.0.0"\n'
            f'  fix_strategy: "deterministic"\n'
            f'  deterministic_tool: "{tools[i-1]}"\n'
            f'  human_review_required: false\n'
            f'  llm_fix_template: "Apply secure {names[i-1].lower()} patterns for {did}"\n'
            f'  blast_radius_notes: "Automated fix for {cid} - {names[i-1]}"\n'
            f'  verification_checks:\n'
            f'    - "Verify {cid} is addressed"\n'
            f'    - "Run tests to confirm no regression"\n'
            f'    - "Scan with security linter to confirm fix"'
        )
        controls.append(entry)

    header = f"# Playbook for: {did}\n# Source: {source}\n# Auto-generated\n\nplaybooks:\n"
    return header + "\n".join(controls) + "\n"


def _resolve_output_dirs(dest: Path) -> tuple[Path, Path]:
    """Resolve (domains_dir, playbooks_dir) under ``dest``.

    Default (repo root): patchi/core/security/{domains,fix-playbooks},
    matching the in-repo taxonomy location. Scratch destinations without a
    patchi/ package get a flat <dest>/{domains,fix-playbooks} layout.
    """
    if (dest / "patchi").is_dir():
        return dest / DOMAINS_DIR, dest / PLAYBOOKS_DIR
    return dest / "domains", dest / "fix-playbooks"


def main() -> None:
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="Regenerate the Patchi security domain + playbook YAML taxonomy."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent.parent.parent,
        help="Output root (defaults to this repository's root directory)",
    )
    args = parser.parse_args()

    domains_dir, playbooks_dir = _resolve_output_dirs(args.out)
    os.makedirs(domains_dir, exist_ok=True)
    os.makedirs(playbooks_dir, exist_ok=True)

    count = 0
    seen_ids = set()
    for did, name, source, ctype, weight, clause, desc, sev, check in DOMAINS:
        if did in seen_ids:
            continue
        seen_ids.add(did)

        domain_yaml = generate_domain_yaml(did, name, source, ctype, weight, clause, desc, sev, check)
        playbook_yaml = generate_playbook_yaml(did, name, source, sev)

        domain_file = domains_dir / f"{did}.yaml"
        playbook_file = playbooks_dir / f"{did}.playbook.yaml"

        domain_file.write_text(domain_yaml, encoding="utf-8")
        playbook_file.write_text(playbook_yaml, encoding="utf-8")

        count += 1

    print(f"Generated {count} domain YAMLs in {domains_dir}")
    print(f"Generated {count} playbook YAMLs in {playbooks_dir}")
    print(f"Total controls: {count * 5}")


if __name__ == "__main__":
    main()
