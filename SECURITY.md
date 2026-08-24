# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Patchi, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security@patchi.dev (or the maintainer directly)
3. Include: description, steps to reproduce, potential impact
4. Allow 48 hours for initial response

## Security Features

Patchi is designed with security in mind:

- **No telemetry** — All data stays on your machine
- **No plaintext keys** — API keys stored as env var references in `.patchi/keys.json`
- **Atomic writes** — Crash-safe file operations (tmp + rename)
- **File locking** — Prevents concurrent data corruption
- **Risk gating** — High-risk patches require explicit approval
- **Contract protection** — Critical flows are protected from risky changes
- **node_modules excluded** — Scanners never touch dependency directories
- **Snapshot rollback** — Every patch apply creates a snapshot for undo
- **Defense pipeline** — Auto-fix high-confidence findings, AI-analyze medium, discard low (opt-in via `--pipeline`)
- **Confidence gating** — Deterministic scoring (zero AI tokens) using method_precision + severity + location - known_fp
- **12 defense action types** — fix_code, update_dependency, block_ip, rotate_secret, patch_config, crypto_fix, auth_middleware, invalidate_session, enforce_rate_limit, suspend_account, block_ws_origin, escalate
- **Multi-package-manager dispatch** — pip, npm, yarn, cargo, go, gem, nuget, composer (auto-detected from project)
- **Runtime request interceptor** — ASGI middleware for real-time injection detection and IP blocking
- **Background scheduler** — Configurable periodic scanning per agent (default 1h, overrides per agent)

## Security Agents (54 total)

Patchi includes 54 security agents covering the full OWASP surface + LLM/business logic/session/WebSocket:

| Agent | Coverage | Module |
|---|---|---|
| AppMapperAgent | Crawl live app, map pages/forms/entry points | `.app_mapper` |
| AuthenticationAuditAgent | Auth flow, password hashing, MFA | `.auth_audit_agent` |
| AuthZAgent | Broken access control, IDOR, privilege escalation | `.authz_agent` |
| BlastRadiusAgent | Static blast radius analysis | `.blast_radius` |
| BrowserTesterAgent | Playwright XSS/SQLi/auth bypass testing | `.browser_tester` |
| BusinessLogicAgent | Mass assignment, excessive data exposure, IDOR, rate limits | `.business_logic_agent` |
| CDNCacheSecurityAgent | CDN cache poisoning, origin exposure | `.cdn_cache_agent` |
| CatchBlockAuditor | Empty/bare catch blocks, suppressed errors | `.catch_block_auditor` |
| CloudWAFDetector | Cloud WAF configuration and bypass detection | `.cloud_waf_detector` |
| ComplianceAgent | PCI DSS, HIPAA, GDPR, SOX | `.compliance_agent` |
| ConfigAuditAgent | Semgrep CE SAST scanning | `.security_config` |
| ContainerScannerAgent | Container image CVE scanning | `.container_scanner` |
| CORSAuditor | CORS configuration | `.security_probe` |
| CryptoAgent | Weak hashing, weak encryption, hardcoded keys | `.crypto_agent` |
| CVEMonitorAgent | OSV API CVE monitoring | `.cve_monitor` |
| DependencyCVEChecker | Known CVEs in dependencies | `.security_probe` |
| DependencyVulnerabilityAgent | Multi-ecosystem CVE checks | `.dependency_vulnerability_agent` |
| DNSSecurityAgent | DNS configuration, SPF/DKIM/DMARC | `.dns_security_agent` |
| EmailAuthenticationAgent | Email security, SPF/DKIM/DMARC | `.email_authentication_agent` |
| EnvVarValidator | Environment variable validation | `.env_var_validator` |
| EvidenceAgent | Screenshot/video evidence capture | `.evidence` |
| FalcoRuntimeAgent | Falco runtime security monitoring | `.falco_runtime_agent` |
| GovernanceAgent | Action logging + policy gate | `.governance` |
| HeaderAuditAgent | HTTP security headers | `.security_config` |
| HistoryAgent | Scan history + lifecycle tracking | `.history` |
| IaCScannerAgent | Docker, K8s, Terraform scanning | `.iac_scanner` |
| InsecureRandomnessAgent | Weak PRNG usage detection | `.insecure_randomness_agent` |
| InjectionAgent | SQLi, XSS, command injection, path traversal | `.injection_agent` |
| JWTSecurityAgent | JWT implementation issues | `.jwt_agent` |
| KubernetesAgent | Kubernetes security configuration | `.kubernetes_agent` |
| LLMSecurityAgent | Prompt injection, insecure output exec/eval | `.llm_security_agent` |
| MisconfigAgent | Debug flags, default creds | `.misconfig_agent` |
| MobileSecurityAgent | Mobile platform security issues | `.mobile_security_agent` |
| NetworkAgent | SSL/TLS config, cipher suites | `.network_agent` |
| PlanAuditorAgent | Codebase vs build plan audit | `.plan_auditor` |
| PolicyEngineAgent | YAML/JSON policy enforcement | `.policy_engine` |
| PreCheckAgent | Layer 0 banned-API + lint checks | `.prechecks` |
| PrivacyAgent | PII handling, GDPR/CCPA | `.privacy_agent` |
| PushNotificationAgent | Push notification security | `.push_notification_agent` |
| RateLimitAuditor | Rate limiting on auth routes | `.security_config` |
| RedTeamAgent | Attack surface analysis | `.red_team_agent` |
| RuntimeValidatorAgent | Runtime header/TLS/method checks | `.runtime_validator` |
| SamlSSOAgent | SAML SSO security configuration | `.saml_sso_agent` |
| SecretScanner | Hardcoded credentials, API keys | `.security_taint` |
| SecretsGuard | Pre-apply secrets gate, config/CI/Docker scanning | `.secrets_guard` |
| SecretsRuntimeAgent | Runtime secret detection | `.secrets_runtime_agent` |
| SecurityProber | Active probing (dev mode only) | `.security_probe` |
| SensitiveDataAgent | PII exposure | `.sensitive_data_agent` |
| ServiceMeshAgent | Service mesh security | `.service_mesh_agent` |
| SessionManagementAgent | Session fixation, cookie flags, timeout/logout | `.session_management_agent` |
| SSRFProtectionAgent | Server-side request forgery | `.ssrf_agent` |
| SupplyChainAgent | Typosquatting, pinning, license compliance | `.supply_chain` |
| TaintAnalyzer | Data flow from sources to sinks | `.security_taint` |
| WebSocketSecurityAgent | Unencrypted ws://, origin validation, message security | `.websocket_security_agent` |

## Scope

Security issues in the following are in scope:
- Patchi CLI and Web UI
- AI key storage and handling
- Patch application and rollback
- Hosted mode anomaly detection

Out of scope:
- The AI providers themselves (OpenAI, Anthropic, etc.)
- Dependencies (report to their maintainers)
