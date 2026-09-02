# BUILD PLAN — Patchi Security-Native Upgrade

**Created:** June 2026
**Based on:** Coding Agent Tools — Gaps, Solutions & Open-Source Integrations research
**Scope:** Close the 12 critical deficiency domains identified in coding agent security research
**Architecture:** Integrate into patchi's existing agent/coordinator/agent-group system
**Status:** Phases 0-16 fully built and registered. See below for files-5 reconciliation.

---

## The Core Problem (TL;DR)

Research shows coding agents produce **functionally correct but insecure code**:
- 84.4% functional correctness vs 7.8% security correctness (SusVibes)
- 4,241 CWE instances in 7,700+ AI-generated files
- 40% vulnerability rate in AI-generated code (NYU)
- Only 10.5% of agent solutions were secure vs 61% functionally correct (CMU)

**Patchi already has the foundation.** The fix is not rebuilding — it's closing gaps and wiring existing + new tools into the pipeline.

---

## Gap-to-Patchi Map: What Exists vs What's Missing

| Research Gap | Patchi Has Today | What's Missing | Integration Target |
|---|---|---|---|
| GAP 1: Runtime Security Validation | `SecurityProber` (dev-only, basic payloads) | Auth bypass, race conditions, business logic, session flaws | Expand payloads + move out of dev-only |
| GAP 2: Deterministic SAST | `ConfigAuditAgent` (Semgrep CE), `TaintAnalyzer` (regex) | No TruffleHog, no SCA orchestration, no secrets-in-generated-code | Add TruffleHog, unify output format |
| GAP 3: Plan-Auditing | Nothing | Cannot validate code against requirements | New: `PlanAuditorAgent` |
| GAP 4: Security Test Gen | `UnitTestAgent`, `APITestAgent` (functional only) | No fuzz/injection/auth-boundary tests | New: `SecurityTestAgent` |
| GAP 5: Fix Verification Loop | `SecurityFixer` applies patches, no re-scan | Fix not verified against scanner | Add re-scan gate |
| GAP 6: Supply Chain Security | `DependencyCVEChecker` (OSV), `DependencyVulnerabilityAgent` (unregistered) | No SBOM, no license compliance, no typosquatting | Extend with Syft, license checker |
| GAP 7: Deployment Security | `HeaderAuditAgent`, `CORSAuditor`, `MisconfigAgent` | No container/IaC/cloud scanning | New: `ContainerScannerAgent`, `IaCScannerAgent` |
| GAP 8: Continuous Monitoring | Hosted mode anomaly/watchlist (live logs) | No dependency CVE re-monitoring | New: `CVEMonitorAgent` |
| GAP 9: Multi-Layer Orchestration | Coordinator parallel, no correlation | No deduplication, no cross-agent correlation | New: `SecurityOrchestrator` |
| GAP 10: Attack Surface Mapping | `RouteMapScanner`, `ContractScanner` | No entry point enumeration, no trust boundaries | Extend contract + route mapper |
| GAP 11: Security Policy Enforcement | `ComplianceAgent` (unregistered, pattern match) | No org-specific policy rules, no CI gates | New: `PolicyEngine` |
| GAP 12: Adversarial Testing | `SecurityProber` (basic, dev-only) | No red-team, no fuzzing, no exploit scenarios | New: `RedTeamAgent` + fuzzer |

---

## What's Already Built (Use It)

### Existing Security Agents (13 registered in security_agents.py)

| Agent | Module | Status |
|---|---|---|
| `TaintAnalyzer` | `security_taint.py` | Registered, working |
| `SecretScanner` | `security_taint.py` | Registered, working |
| `ConfigAuditAgent` | `security_config.py` | Registered, working (Semgrep CE) |
| `HeaderAuditAgent` | `security_config.py` | Registered, working |
| `RateLimitAuditor` | `security_config.py` | Registered, working |
| `CORSAuditor` | `security_probe.py` | Registered, working |
| `DependencyCVEChecker` | `security_probe.py` | Registered, working (OSV API) |
| `SecurityProber` | `security_probe.py` | Registered, dev-only |
| `MisconfigAgent` | `misconfig_agent.py` | Registered, working |
| `JWTSecurityAgent` | `jwt_agent.py` | Registered, working |
| `SensitiveDataAgent` | `sensitive_data_agent.py` | Registered, working |
| `AuthenticationAuditAgent` | `auth_audit_agent.py` | Registered, working |
| `SSRFProtectionAgent` | `ssrf_agent.py` | Registered, working |

### Existing Security Agents (unregistered — files exist, NOT imported)

| Agent | Module | Status |
|---|---|---|
| `InjectionAgent` | `injection_agent.py` | File exists, NOT registered |
| `AuthZAgent` | `authz_agent.py` | File exists, NOT registered |
| `CryptoAgent` | `crypto_agent.py` | File exists, NOT registered |
| `NetworkAgent` | `network_agent.py` | File exists, NOT registered |
| `PrivacyAgent` | `privacy_agent.py` | File exists, NOT registered |
| `DependencyVulnerabilityAgent` | `dependency_vulnerability_agent.py` | File exists, NOT registered |
| `ComplianceAgent` | `compliance_agent.py` | File exists, NOT registered |

### Existing Infrastructure

- `Coordinator` — parallel/sequential/batched via ThreadPoolExecutor
- `AgentGroup` enum — SCANNER, FIX, TEST, SECURITY, GUARD
- `@register` decorator — auto-registration on import
- `AgentInput` / `AgentResult` — standard I/O contract
- `Finding` dataclass — file, line, severity, cwe, rule, message, fix_hint
- `health.py` — 0-100 score, security weighted 35%
- `risk_gate.py` — risk assessment before patch application
- `snapshot.py` — file snapshots for undo/rollback
- `fix_agents.py` — `SecurityFixer` (AI-powered vulnerability patches)

---

## Implementation Phases

### PHASE 0: Register Unregistered Agents (1-2 hours)
**Priority: P0 — Quick wins, zero new code**

These agents already exist as files. They just need imports in `security_agents.py`.

**Files to edit:**
- `patchi/core/security/security_agents.py` — add imports for 7 unregistered agents
- `patchi/cli/commands/security_cmd.py` — expand scan type choices
- `tests/test_security_agents.py` — add tests for newly registered agents

**Agents to register:**
1. `InjectionAgent` — SQLi, XSS, command injection, path traversal
2. `AuthZAgent` — broken access control, IDOR, privilege escalation
3. `CryptoAgent` — weak hashing, weak encryption, hardcoded keys
4. `NetworkAgent` — SSL/TLS config, weak ciphers, HTTPS
5. `PrivacyAgent` — PII handling, GDPR patterns
6. `DependencyVulnerabilityAgent` — CVE checks via OSV API
7. `ComplianceAgent` — PCI DSS, HIPAA, GDPR, SOX

**Done when:** `p security --all` runs all 20 security agents, tests pass.

---

### PHASE 1: Scanner Orchestration & Deduplication (P0)
**Priority: P0 — Foundation for everything else**

The current `Coordinator` runs agents but does not correlate findings. Multiple agents flagging the same issue creates noise.

**New module:** `patchi/core/security/orchestrator.py`

**What it does:**
- Receives all `AgentResult` objects from security scan
- Deduplicates findings (same file + same line + overlapping CWE = merge)
- Correlates across agents (SecretScanner + SensitiveDataAgent both find same secret = one finding with dual confirmation)
- Assigns composite risk score (CVSS-like severity + exploitability + confidence)
- Maps findings to OWASP Top 10 and CWE IDs
- Outputs unified `SecurityReport` dataclass

**Integration:**
- `Coordinator` calls `SecurityOrchestrator.correlate(results)` after parallel agent execution
- `health.py` `_compute_security()` uses `SecurityReport` instead of raw agent results
- `p security --report` outputs unified report
- `p report` includes security orchestration output

**Key design:** Pure Python, no external deps. Uses finding metadata (file, line, CWE, severity) for correlation. LLM layer optional — deterministic dedup first, AI disambiguation second.

**Done when:** `p security --all` produces deduplicated, correlated findings. No duplicate warnings for same issue.

---

### PHASE 2: Detect-Fix-Verify Loop (P0)
**Priority: P0 — Most impactful single capability**

Currently: `SecurityFixer` applies a patch and stops. No verification that the fix works.

**Changes to:**
- `patchi/core/fix/fix_agents.py` — `SecurityFixer._run()` gains re-scan step
- `patchi/core/agents/coordinator.py` — fix pipeline gains verification gate

**Flow:**
```
Finding -> SecurityFixer generates patch -> applier writes file
    -> Re-run same scanner agent that found the issue
    -> If finding still present -> retry with different approach (max 2)
    -> If finding gone -> mark verified
    -> Run functional tests -> confirm no regression
    -> Only present verified fixes to user
```

**Done when:** After `p fix --security`, re-running `p security` shows the specific finding is gone. Tests still pass.

---

### PHASE 3: Secrets Scanning Upgrade (P0)
**Priority: P0 — Pre-apply secret gate**

The current `SecretScanner` uses Gitleaks subprocess + regex fallback. Missing:
- No verification of detected secrets (real vs test data)
- No check for secrets in AI-generated code before it's written
- No scan of config/CI files beyond source code

**New module:** `patchi/core/security/secrets_guard.py`

**What it does:**
- Wraps Gitleaks (MIT, already used) + adds verification step
- Checks generated code for secrets BEFORE applying patches (integrate with risk_gate)
- Scans `.env`, `docker-compose.yml`, Kubernetes manifests, CI configs
- Generates `.gitignore` entries for discovered secret files

**Integration:**
- `risk_gate.py` — secrets check added to pre-apply validation
- `SecurityFixer` — verify generated fix doesn't introduce new secrets
- `fix_agents.py` `EnvFixer` — enhanced secret removal + .env.example generation
- CLI: `p security secrets` gains `--verify` flag

**Done when:** `p security secrets` detects hardcoded keys in source, config, CI files. `p fix --security` auto-removes secrets and generates .env.example. Pre-apply gate blocks patches that introduce secrets.

---

### PHASE 4: Dependency Security Deepening (P1)
**Priority: P1 — Supply chain security**

Current: `DependencyCVEChecker` checks OSV API for known CVEs.

**New module:** `patchi/core/security/supply_chain.py`

**What it does:**
- SBOM generation using Syft (SPDX + CycloneDX format)
- License compliance checking (flag GPL in proprietary code, flag unknown licenses)
- Typosquatting detection (package name similarity scoring)
- Dependency pinning validation (are versions pinned or floating?)
- Outdated dependency detection (compare against latest stable)
- Generate `SECURITY.md` with vulnerability disclosure policy

**Integration:**
- `DependencyCVEChecker` enhanced with SBOM output
- `p security deps` gains `--sbom`, `--licenses`, `--outdated` flags
- `p report export` includes SBOM in JSON output
- New CLI: `p deps` command for dependency-focused scan

**Done when:** `p security deps --sbom` generates CycloneDX SBOM. `p deps --licenses` flags problematic licenses. `p deps --outdated` lists packages with available updates.

---

### PHASE 5: Security Test Auto-Generation (P1)
**Priority: P1 — Close the test gap**

Current: `UnitTestAgent`, `APITestAgent` generate functional tests only.

**New module:** `patchi/core/testing/security_test_agent.py`

**What it does:**
- For each route/endpoint found by `RouteMapScanner`:
  - Authentication bypass test attempts
  - SQL injection payload tests (per detected DB driver)
  - XSS payload injection tests
  - CSRF token validation tests
  - Rate limiting tests (rapid-fire requests)
  - Header validation tests
  - CORS origin tests (malicious origins)
- For file upload endpoints:
  - Malicious file type upload tests
  - Path traversal in filename tests
- For WebSocket endpoints:
  - Cross-site WebSocket hijacking tests

**Integration:**
- `p test security` — new test mode
- `p test all` includes security tests in batch
- `APITestAgent` enhanced with security probe generation
- Outputs pytest files in `tests/security/` directory
- Results feed into health score test coverage calculation

**Done when:** `p test security` generates and runs security-focused tests for all detected routes. Tests are saved to `tests/security/` for re-running.

---

### PHASE 6: Runtime Security Validation (P2)
**Priority: P2 — DAST for web apps**

Current: `SecurityProber` does basic active probing but is dev-mode only.

**Changes to:**
- `patchi/core/security/security_probe.py` — expand `SecurityProber`
- New: `patchi/core/security/runtime_validator.py`

**What it does:**
- Deploy generated app to isolated container (Docker)
- Run OWASP ZAP scan against running app (DAST)
- Test with authentication (login + scan authenticated pages)
- Verify security headers on actual HTTP responses
- Validate TLS/SSL configuration (testssl.sh or sslyze)
- Check for server information leakage
- Test for HTTP method tampering

**Integration:**
- `p security runtime` — new scan type
- `SecurityProber` moved out of dev-only gate with proper sandboxing
- `HeaderAuditAgent` enhanced with actual HTTP response validation
- `NetworkAgent` enhanced with TLS testing
- Requires Docker for containerized sandbox (optional, graceful fallback)

**Done when:** `p security runtime` spins up app in Docker, runs ZAP scan, reports runtime vulnerabilities not found by static analysis.

---

### PHASE 7: Plan-Auditing Engine (P2)
**Priority: P2 — Unique differentiator, no competitor does this**

**New module:** `patchi/core/security/plan_auditor.py`

**What it does:**
- Ingests structured requirements (OpenAPI specs, architecture docs, compliance checklists)
- Maps requirements to specific code elements (endpoints, functions, data flows)
- Validates:
  - All specified auth requirements are implemented
  - API endpoints match defined authorization matrices
  - Data handling complies with GDPR/SOC2/HIPAA
  - Generated infrastructure meets CIS benchmarks
  - Code implements controls from threat model
- Reports gaps where requirements are not implemented

**Integration:**
- `p audit plan <spec-file>` — audit code against a spec
- `p security --compliance <framework>` — audit against SOC2/HIPAA/PCI-DSS
- `ComplianceAgent` enhanced with plan-aware validation
- Output: compliance report with pass/fail per requirement

**Done when:** `p audit plan openapi.yaml` shows which endpoints comply with the spec and which don't. `p security --compliance hipaa` maps findings to HIPAA controls.

---

### PHASE 8: IaC and Container Security (P2)
**Priority: P2 — Deployment security**

**New modules:**
- `patchi/core/security/iac_scanner.py`
- `patchi/core/security/container_scanner.py`

**What they do:**
- Scan Dockerfiles for: running as root, exposed ports, hardcoded secrets, outdated base images
- Scan docker-compose.yml for: privileged containers, host network mode, volume mounts
- Scan Kubernetes manifests for: securityContext, resource limits, network policies
- Scan Terraform/CloudFormation for: public S3 buckets, open security groups, unencrypted storage
- Scan Helm charts for: default values with security implications
- Validate against CIS Docker Benchmark and CIS Kubernetes Benchmark

**Integration:**
- `p security iac` — new scan type
- `p security container` — new scan type
- `p audit` includes IaC scan in full audit
- Uses Checkov (Apache 2.0) as primary engine, Trivy as fallback
- Output: per-file findings with CIS benchmark mapping

**Done when:** `p security iac` scans Dockerfiles, K8s manifests, Terraform files and reports misconfigurations. `p security container` scans container images for CVEs.

---

### PHASE 9: Security Policy Engine (P2)
**Priority: P2 — Organization-specific enforcement**

**New module:** `patchi/core/security/policy_engine.py`

**What it does:**
- YAML/JSON policy definitions (inspired by Checkov)
- Pre-defined policy packs: SOC2, HIPAA, PCI-DSS, CIS Controls
- Custom rule authoring for org-specific requirements
- Block or warn on policy violations during code generation
- Audit trail of all policy decisions

**Integration:**
- `.patchi/policies/` directory for policy files
- `p security policy` — run policy checks
- `p security --policy soc2` — run SOC2 policy pack
- Risk gate consults policy engine before applying patches
- `p report` includes policy compliance status

**Done when:** `p security --policy soc2` checks code against SOC2 controls. Custom policies in `.patchi/policies/` are enforced.

---

### PHASE 10: Continuous Security Monitoring (P3)
**Priority: P3 — Ongoing awareness**

**New module:** `patchi/core/security/cve_monitor.py`

**What it does:**
- Monitor dependency CVE feeds (NVD, GHSA, OSV)
- Re-scan projects when new vulnerabilities are disclosed
- Integrate CISA KEV feed for exploit prioritization
- Generate security advisories for generated projects
- Automated PR creation for security patches (GitHub Actions integration)

**Integration:**
- `p monitor start` — background CVE monitoring
- `p monitor status` — show monitoring state
- Hosted mode integration with existing anomaly/watchlist
- Notifications via existing notification channels

**Done when:** `p monitor start` watches for new CVEs affecting project dependencies and alerts via configured channels.

---

### PHASE 11: Adversarial Testing / Red Team (P3)
**Priority: P3 — Strategic differentiation**

**New module:** `patchi/core/security/red_team_agent.py`

**What it does:**
- Generate adversarial test cases against generated code
- Simulate attacker workflows (reconnaissance to exploitation)
- Use fuzzing (via subprocess: AFL++ for C, Jazzer for JVM, Boofuzz for protocols)
- Perform privilege escalation testing
- Report findings with exploit scenarios and severity

**Integration:**
- `p security redteam` — run red team analysis
- `p test adversarial` — generate and run adversarial tests
- Output: attack tree + exploit scenarios + remediation

**Done when:** `p security redteam` produces an attack tree for the application and identifies exploitation paths.

---

## Open-Source Integration Map

### Tier 1: Already Integrated or Trivial to Add

| Tool | GitHub | Patchi Integration | Action Needed |
|---|---|---|---|
| Semgrep CE | `returntocorp/semgrep` | `ConfigAuditAgent` uses it | No change |
| Gitleaks | `zricethezav/gitleaks` | `SecretScanner` uses it | No change |
| OSV API | `google/osv.dev` | `DependencyCVEChecker` uses it | No change |
| httpx | `encode/httpx` | `CORSAuditor`, `HeaderAuditAgent` use it | No change |

### Tier 2: Add in Phase 1-3

| Tool | GitHub | What It Does | Patchi Module |
|---|---|---|---|
| TruffleHog | `trufflesecurity/trufflehog` | 800+ secret types, live verification | `secrets_guard.py` |
| Syft | `anchore/syft` | SBOM generation (SPDX, CycloneDX) | `supply_chain.py` |
| OSV-Scanner | `google/osv-scanner` | Cross-ecosystem vuln scanning | Already partially via OSV API |
| Checkov | `bridgecrewio/checkov` | IaC security (1000+ policies) | `iac_scanner.py` |
| Trivy | `aquasecurity/trivy` | All-in-one: vulns, IaC, secrets, licenses | `container_scanner.py` |

### Tier 3: Add in Phase 6-11

| Tool | GitHub | What It Does | Patchi Module |
|---|---|---|---|
| OWASP ZAP | `zaproxy/zaproxy` | Full DAST web app scanner | `runtime_validator.py` |
| Nuclei | `projectdiscovery/nuclei` | Template-based vuln scanner | `red_team_agent.py` |
| testssl.sh | `drwetter/testssl.sh` | SSL/TLS configuration scanner | `runtime_validator.py` |
| humble | `rfc-st/humble` | HTTP security headers analyzer | Enhanced `HeaderAuditAgent` |
| AFL++ | `AFLplusplus/AFLplusplus` | Coverage-guided fuzzing | `red_team_agent.py` |
| Boofuzz | `jtpereyda/boofuzz` | Network protocol fuzzing | `red_team_agent.py` |
| Playwright | `microsoft/playwright` | Browser automation for E2E security tests | `security_test_agent.py` |

### Tier 4: Optional / Enterprise

| Tool | GitHub | What It Does | When to Add |
|---|---|---|---|
| CodeQL | `github/codeql` | Deep semantic analysis | Phase 7+ |
| OWASP Amass | `owasp-amass/amass` | Attack surface discovery | Phase 11 |
| DefectDojo | `DefectDojo/django-DefectDojo` | Vuln management platform | Phase 10 |
| Falco | `falcosecurity/falco` | K8s runtime threat detection | Phase 10 |

---

## Architecture: How It All Fits

```
p security (full scan)
    |
    v
+------------------------------------------+
| 1. BRAIN BUILD (existing)                |
|    discovery -> parse -> framework       |
|    -> routes -> import_graph -> contract |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 2. SECURITY AGENTS (parallel)            |
|    13 existing + 7 newly registered      |
|    = 20 agents total                     |
|    All run via Coordinator ThreadPool    |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 3. SECURITY ORCHESTRATOR (new - Phase 1) |
|    Deduplicate findings                  |
|    Cross-agent correlation               |
|    Composite risk scoring                |
|    OWASP/CWE mapping                     |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 4. SECURITY REPORT (output)              |
|    Unified findings with risk scores     |
|    Feeds into health.py                  |
|    Feeds into p report                   |
|    Feeds into notifications              |
+------------------------------------------+

p fix --security (fix pipeline)
    |
    v
+------------------------------------------+
| 1. FINDINGS from security scan           |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 2. RISK GATE (existing)                  |
|    + SECRETS GATE (new - Phase 3)        |
|    + POLICY GATE (new - Phase 9)         |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 3. SECURITY FIXER (existing)             |
|    AI generates targeted patch           |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 4. RE-SCAN (new - Phase 2)              |
|    Re-run original scanner agent         |
|    Verify finding is resolved            |
|    Max 2 retries                         |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 5. REGRESSION CHECK (existing)           |
|    Run functional tests                  |
|    Confirm no breakage                   |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 6. APPLY (existing)                      |
|    Snapshot + write to disk              |
+------------------------------------------+

p test security (security test generation)
    |
    v
+------------------------------------------+
| 1. ROUTE MAP from brain (existing)       |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 2. SECURITY TEST AGENT (new - Phase 5)   |
|    Generate per-route security tests     |
|    SQLi, XSS, CSRF, auth bypass, etc.    |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 3. TEST RUNNER (existing Playwright)     |
|    Execute generated security tests      |
|    Collect pass/fail results             |
+------------------------------------------+
    |
    v
+------------------------------------------+
| 4. RESULTS                               |
|    Save to tests/security/               |
|    Feed into health score                |
|    Report to user                        |
+------------------------------------------+
```

---

## Priority Matrix

| Phase | Feature | Impact | Effort | Priority | Key Dependencies |
|---|---|---|---|---|---|
| 0 | Register unregistered agents | High | Low | P0 | Existing files only |
| 1 | Security orchestrator | High | Medium | P0 | Finding dedup logic |
| 2 | Detect-fix-verify loop | High | Medium | P0 | Scanner integration |
| 3 | Secrets guard | High | Low | P0 | Gitleaks (already used) |
| 4 | Supply chain security | High | Medium | P1 | Syft, OSV-Scanner |
| 5 | Security test generation | High | Medium | P1 | Playwright (already a dep) |
| 6 | Runtime validation | High | High | P2 | Docker, ZAP |
| 7 | Plan-auditing | Very High | High | P2 | Custom parser |
| 8 | IaC + container security | Medium | Medium | P2 | Checkov, Trivy |
| 9 | Security policy engine | High | High | P2 | YAML engine |
| 10 | Continuous monitoring | Medium | Medium | P3 | OSV API, CISA KEV |
| 11 | Red team / adversarial | High | Very High | P3 | AFL++, Boofuzz |

---

## Key Research Sources

- Cybedefend — "AI Vulnerability Remediation With Coding Agents" (2026)
- Endor Labs — "Agent Security League" (2026). SusVibes benchmark.
- Fiddler AI — "AI Coding Agent Security: Threat Models and Controls" (2026)
- Carnegie Mellon / SusVibes — 13 agent+model combinations evaluated.
- arxiv — "Can Open-Source LLM Agents Replace SAST Tools?" (2025)
- arxiv — "AI Copilot with Context-Based RAG" (2024)
- OWASP — CRS v4, ASVS 4.0, Top 10 2021
- Tool documentation — Semgrep, Trivy, Grype, Checkov, TruffleHog, ZAP, Nuclei

---

## Strategic Summary

**The moat is not better prompts — it's deeply integrated security infrastructure.**

Patchi's advantage:
1. **Deterministic scanning** (Semgrep/Gitleaks) + LLM reasoning for remediation
2. **Plan-auditing capability** (no competitor does this)
3. **Closed-loop fix verification** (no competitor does this)
4. **20-agent security surface** (largest agent count in any coding tool)
5. **Continuous security monitoring** (no competitor does this)

This creates a fundamentally different product: not just a coding agent, but a **secure software delivery agent**.

---

## Layered Pre-Check Architecture

Cheap checks run first and gate whether the expensive ones need to run:

```
Layer 0: Cheap deterministic checks   (rg/grep counts, lint, format)      <1 sec
Layer 1: Real scanners                (Semgrep, Gitleaks, OSV-Scanner)    seconds
Layer 2: Fix → Verify loop            (re-run the specific rule that fired)
Layer 3: Governance / audit           (who/what changed, policy gates)
Layer 4: Operational layer            (history, analytics, logs — not in the hot path)
Layer 5: Runtime browser testing      (DAST, evidence capture, demo mode)
Layer 6: Blast radius simulation      (sandbox fix, behavioral diff, apply gate)
```

Build order: **0 → 1 → 2 → 4 → 3 → 5 → 6**. Core scanning + verify loop first, history/analytics next, governance once auto-apply exists, browser testing once static pipeline is solid, blast radius last.

---

### PHASE 12: Cheap Pre-Checks (Layer 0)
**Priority: P0 — Instant gate before expensive scans**

These run before anything heavy, and most findings cost zero LLM tokens — they're pure pattern math.

**New module:** `patchi/core/security/prechecks.py`

**What it does:**

`patchi_pattern_count(path, pattern)` — wraps `rg -o '<pattern>' <path> | wc -l` style counting.
- Verify a refactor finished (old name count == 0)
- Check banned-API usage (`eval(`, `pickle.loads(`, `exec(` — count should always be 0 in clean code)
- Confirm a fix didn't get half-applied across multiple files

`patchi_lint_check(path, language)` — wraps ruff/eslint/etc. Catches style and obvious-bug-shaped issues before a real scanner runs. Near-instant, filters noise out of the expensive layer.

`patchi_diff_stat(before, after)` — before/after line counts on a change. Cheap guardrail against an agent silently rewriting way more than it was asked to.

**Integration:**
- `Coordinator` calls pre-checks before dispatching to Layer 1 scanners
- If pre-checks find zero issues, expensive scanners can be skipped or deprioritized
- `SecurityFixer` uses `patchi_pattern_count` to confirm fixes before re-scanning

**Done when:** `p security --fast` runs pre-checks in <1 sec, skips heavy scanners when nothing suspicious is found. `patchi_pattern_count` works for banned-API checks.

---

### PHASE 13: Governance & Audit (Layer 3)
**Priority: P2 — Matters once Patchi can auto-apply fixes**

**New module:** `patchi/core/security/governance.py`

**What it does:**

`patchi_action_log` — every tool call Patchi makes (file read/write, shell command) gets logged locally to SQLite. Same pattern as `safedep/gryph`. No cloud telemetry.

`patchi_policy_gate(action)` — before any destructive action (auto-applying a fix), check against a YAML allow/deny policy:
```yaml
# .patchi/policies/default.yaml
never_touch:
  - ".env"
  - "docker-compose.yml"
  - "*.key"
auto_apply_max_severity: medium
require_confirmation_above: high
```

**Integration:**
- `RiskGate` consults policy engine before applying patches
- `SecurityFixer` logs every action to SQLite via `patchi_action_log`
- `.patchi/policies/` directory for policy files
- `p security policy` — run policy checks
- `p security --policy soc2` — run SOC2 policy pack (future, with OPA/Rego)

**Done when:** All auto-applied fixes go through the policy gate. `p security policy` checks code against YAML policies. Every Patchi action is logged to local SQLite.

---

### PHASE 14: Operational Layer — Analytics, Logs, History (Layer 4)
**Priority: P1 — Makes Patchi feel like a product**

This doesn't affect a single scan but makes findings trackable over time. None of it blocks the hot path — it's all write-after-the-fact.

**New module:** `patchi/core/security/history.py`

**Schema:**

```sql
-- Scan history
CREATE TABLE scan_history (
    scan_id TEXT PRIMARY KEY,
    timestamp TEXT,
    repo_path TEXT,
    tool TEXT,
    findings_count INTEGER,
    severity_breakdown TEXT,  -- JSON
    duration_ms INTEGER
);

-- Individual findings (track life of each issue)
CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT,
    rule_id TEXT,
    file TEXT,
    line INTEGER,
    severity TEXT,
    status TEXT,  -- open | fixed | verified | false_positive
    first_seen TEXT,
    resolved_at TEXT,
    evidence_path TEXT  -- screenshot/video path from Layer 5
);
```

**Why the findings table matters:** it answers "how long from finding → verified fix?" — the actual product metric, way more meaningful than "number of scans run."

**Analytics derivable from these tables (free):**
- Trend line: total open findings over time
- Mean time-to-fix per severity
- Most common rule violations
- False-positive rate per rule (suppress noisy rules)

**Logs** — separate append-only log of every tool call + result for debugging. Rotate/archive old logs.

**NOT building yet:** a dashboard UI. Get the tables right first.

**Integration:**
- `Coordinator` writes scan results to `scan_history` after every run
- `SecurityOrchestrator` writes individual findings to `findings` table
- `patchi_verify_fix` updates `findings.status` to "verified"
- `p security history` — show scan history
- `p security analytics` — show trend data

**Done when:** `p security history` shows past scans with finding counts. `p security analytics` shows trend lines. Every finding has a tracked lifecycle (open → fixed → verified).

---

### PHASE 15: Runtime Browser Testing (Layer 5)
**Priority: P2 — Closes Gap #1 (runtime validation) and Gap #12 (adversarial testing)**

The things Semgrep/Gitleaks/OSV-Scanner structurally cannot do because they only read code, never run it.

**New modules:**
- `patchi/core/security/app_mapper.py`
- `patchi/core/security/browser_tester.py`
- `patchi/core/security/evidence.py`

**`patchi_map_app(url)` — built on Crawl4AI**
Crawls the live deployed app and returns a structured map: every page, every form, every link, every input field. This runs *before* any testing starts — without it the testing agent explores blind.

Output:
```
{
  pages: [{url, title, forms: [...], links: [...]}],
  forms: [{action, method, fields: [{name, type}]}],
  total_entry_points: N
}
```

**`patchi_browser_test(url, map, test_plan)` — built on browser-use / Playwright**
Drives a real browser through the map:
- Tries logging in with bad/empty credentials → auth bypass check
- Submits each form field with injection payloads (script tags, SQL fragments) → real XSS/injection check
- Clicks every button/link → coverage + "does anything visibly break"
- Tries accessing pages without the right session/role → authorization check

This is exploratory, not pattern-matched like ZAP/Nuclei — it finds things that only show up when something is actually *used* the way an attacker would use it.

**Evidence capture (automatic during tests):**
```python
page.screenshot(path=f"/evidence/{scan_id}/{finding_id}/step_{n}.png")
```
Store path in `findings.evidence_path` column. A finding becomes a screenshot of the XSS payload executing in a real browser — demonstrated, not theoretical.

**Demo mode (marketing, built last):**
Same engine, pointed at a clean test app, scripted run with full session recording:
```python
context = browser.new_context(record_video_dir="demo_recordings/")
```
Produces a video of Patchi finding and flagging an issue — README hero GIF / social post material. Keep "evidence mode" and "demo mode" as distinct flags from day one.

**Integration:**
- `p security runtime` — map app then run browser tests
- `p security runtime --evidence` — capture screenshots/video for each finding
- `p security demo` — demo mode on clean test app
- Findings with evidence feed into `findings.evidence_path`
- Requires Playwright (already a dependency)

**Done when:** `p security runtime` crawls a live app, runs browser-based security tests, captures evidence screenshots. `p security demo` produces a recorded video of a finding.

---

### PHASE 16: Blast Radius Simulation (Layer 6)
**Priority: P2 — Prevents cascade explosions and load-bearing bug breakage**

Core principle: **never apply a fix blind. Simulate it in a sandbox, measure what changes, gate the apply on the result.**

**New module:** `patchi/core/security/blast_radius.py`

**Step 1 — Static blast radius (before proposing the fix)**
Reuse `patchi_pattern_count` from Phase 12 — count every reference to the symbol/package being changed. High count = wide blast radius = proceed carefully. Low count = safe to move faster.

**Step 2 — Dependency tree dry-run**
For dependency fixes — never run the real install first:
```bash
npm install --dry-run   # shows what WOULD change, writes nothing
```
Diff the would-be lockfile against current. Count transitive package changes and new peer-dependency warnings. Surface that diff before anything is committed.

**Step 3 — Behavioral diff (catches "load-bearing bug" case)**
Reuses Phase 15's browser-use agent:
1. Run browser-use test pass against current app → behavioral baseline
2. Apply proposed fix in isolated sandbox (git worktree, never the real repo)
3. Run same browser-use test pass against sandboxed, fixed version
4. Diff the two results

The question isn't "is the fix correct" — it's "did anything that used to work, stop working."

**Step 4 — The apply gate**

| Blast radius | Dependency diff | Behavioral diff | Action |
|---|---|---|---|
| Low | Clean | No regressions | Auto-apply |
| Anything else | — | — | Stop. Show human a report with what changed + behavioral diff screenshots. Let them decide. |

**Severity reframing:** raw CVSS says how bad something *could* be — not whether the app actually calls that code path. Better signals:
- **Reachability** — is the flagged code path actually called by this app?
- **Blast radius** — how much would fixing this touch?

A finding with low reachability + high blast radius should rank *below* one with high reachability + low blast radius, even if the first has a scarier CVSS number.

**Integration:**
- `patchi_blast_radius(symbol_or_package)` — static reference count + dependency dry-run diff
- `patchi_behavioral_diff(finding_id)` — browser-use baseline → sandbox fix → re-run → diff
- `patchi_apply_gate(finding_id)` — combines all three signals into auto-apply / stop-and-report
- `RiskGate` enhanced with blast radius data
- `SecurityFixer` runs apply gate before writing changes

**Done when:** `p fix --security` shows blast radius for each fix. Dependency fixes include dry-run diff. Behavioral diffs produce before/after screenshots. Auto-apply only fires when all three signals are clean.

---

## Verified Open-Source Tool Directory

### SAST (static code scanning)
- **Semgrep** (`semgrep/semgrep`) — fast, rule-based, 30+ languages, CI-native. CE is single-file/function scope; cross-file taint needs paid platform.
- **CodeQL** (`github/codeql`) — deep semantic/interprocedural analysis, GitHub-native.
- **Bandit** (Python), **gosec** (Go), **Brakeman** (Ruby/Rails), **eslint-plugin-security** (JS/Node)
- **SonarQube Community Edition** — multi-language SAST + code quality

### Secrets scanning
- **Gitleaks** (`gitleaks/gitleaks`) — 26,400+ stars, regex + entropy, 150+ secret types
- **TruffleHog** (`trufflesecurity/trufflehog`) — live verification (calls cloud APIs to check if credentials are valid)
- **detect-secrets** (Yelp) — baseline-file workflow for legacy repos
- **Trivy's secrets module** — free if already running Trivy

### SCA / dependency & supply chain
- **OSV-Scanner** (`google/osv-scanner`) — cross-ecosystem vuln DB, already in Patchi
- **Trivy** (`aquasecurity/trivy`) — 31,000+ stars, vulns + IaC + secrets + container + SBOM
- **Grype** (`anchore/grype`) — CVSS + EPSS + CISA KEV composite risk scoring
- **Syft** (`anchore/syft`) — SBOM generation (SPDX, CycloneDX)

### DAST (runtime web app scanning)
- **OWASP ZAP** (`zaproxy/zaproxy`) — open-source default, SPA-aware crawler as of v5.3
- **Nuclei** (`projectdiscovery/nuclei`) — 11,000+ templates for known CVEs/misconfigs

### IaC / container / cloud
- **Checkov** (`bridgecrewio/checkov`) — Terraform/CloudFormation/K8s/Helm, 1,000+ policies
- **KICS** (Checkmarx) — Rego-based IaC scanner, 2,400+ queries

### Agent governance / guardrails
- **`microsoft/agent-governance-toolkit`** — policy enforcement, zero-trust identity, covers OWASP Agentic Top 10
- **`safedep/gryph`** — local audit log of AI coding agent actions (file/shell) to SQLite
- **LlamaFirewall** (Meta) — prompt-injection + insecure-code-generation guardrails
- **Open Policy Agent (OPA)** — standard policy-as-code engine

---

## Updated MCP Tool List

| Tool | Phase | Layer | Cost |
|---|---|---|---|
| `patchi_pattern_count` | 12 | 0 | instant |
| `patchi_lint_check` | 12 | 0 | instant |
| `patchi_diff_stat` | 12 | 0 | instant |
| `patchi_scan_secrets` | existing | 1 | seconds |
| `patchi_scan_dependencies` | existing | 1 | seconds |
| `patchi_scan_code` | existing | 1 | seconds |
| `patchi_verify_fix` | 2 (enhanced) | 2 | seconds |
| `patchi_action_log` | 13 | 3 | instant |
| `patchi_policy_gate` | 13 | 3 | instant |
| `patchi_get_history` | 14 | 4 | instant |
| `patchi_get_analytics` | 14 | 4 | instant |
| `patchi_map_app` | 15 | 5 | seconds |
| `patchi_browser_test` | 15 | 5 | seconds |
| `patchi_capture_evidence` | 15 | 5 | instant |
| `patchi_demo_record` | 15 | 5 | seconds |
| `patchi_blast_radius` | 16 | 6 | instant |
| `patchi_behavioral_diff` | 16 | 6 | seconds |
| `patchi_apply_gate` | 16 | 6 | instant |

---

## Updated Priority Matrix

| Phase | Feature | Impact | Effort | Priority | Key Dependencies |
|---|---|---|---|---|---|
| 0 | Register unregistered agents | High | Low | P0 | Existing files only |
| 1 | Security orchestrator | High | Medium | P0 | Finding dedup logic |
| 2 | Detect-fix-verify loop | High | Medium | P0 | Scanner integration |
| 3 | Secrets guard | High | Low | P0 | Gitleaks (already used) |
| 4 | Supply chain security | High | Medium | P1 | Syft, OSV-Scanner |
| 5 | Security test generation | High | Medium | P1 | Playwright (already a dep) |
| 6 | Runtime validation | High | High | P2 | Docker, ZAP |
| 7 | Plan-auditing | Very High | High | P2 | Custom parser |
| 8 | IaC + container security | Medium | Medium | P2 | Checkov, Trivy |
| 9 | Security policy engine | High | High | P2 | YAML engine |
| 10 | Continuous monitoring | Medium | Medium | P3 | OSV API, CISA KEV |
| 11 | Red team / adversarial | High | Very High | P3 | AFL++, Boofuzz |
| 12 | Cheap pre-checks (Layer 0) | High | Low | P0 | ripgrep, ruff/eslint |
| 13 | Governance & audit (Layer 3) | High | Medium | P2 | SQLite, YAML policy |
| 14 | Operational layer (Layer 4) | Medium | Medium | P1 | SQLite |
| 15 | Runtime browser testing (Layer 5) | Very High | High | P2 | Crawl4AI, browser-use, Playwright |
| 16 | Blast radius simulation (Layer 6) | Very High | Very High | P2 | Phase 12 + Phase 15 |

---

## Key Research Sources

- Cybedefend — "AI Vulnerability Remediation With Coding Agents" (2026)
- Endor Labs — "Agent Security League" (2026). SusVibes benchmark.
- Fiddler AI — "AI Coding Agent Security: Threat Models and Controls" (2026)
- Carnegie Mellon / SusVibes — 13 agent+model combinations evaluated.
- arxiv — "Can Open-Source LLM Agents Replace SAST Tools?" (2025)
- arxiv — "AI Copilot with Context-Based RAG" (2024)
- OWASP — CRS v4, ASVS 4.0, Top 10 2021
- Tool documentation — Semgrep, Trivy, Grype, Checkov, TruffleHog, ZAP, Nuclei

---

## Strategic Summary

**The moat is not better prompts — it's deeply integrated security infrastructure.**

Patchi's advantage:
1. **Deterministic scanning** (Semgrep/Gitleaks) + LLM reasoning for remediation
2. **Plan-auditing capability** (no competitor does this)
3. **Closed-loop fix verification** (no competitor does this)
4. **20-agent security surface** (largest agent count in any coding tool)
5. **Continuous security monitoring** (no competitor does this)
6. **Cheap pre-check gate** (instant deterministic checks before expensive scans)
7. **Blast radius simulation** (never apply a fix blind)
8. **Runtime browser testing** (real browser evidence, not just pattern matching)

---

## files-5 Reconciliation — July 4 2026

All Phases 0-16 above are fully built. The files-5 planning documents (`files-5/` directory) propose a next-generation architecture:

| files-5 Concept | Current Codebase | Action |
|----------------|-----------------|--------|
| **Governor** — Pipeline state machine (SCAN→TEST→FIX→REVERIFY) | `Coordinator.run_groups()` handles agent dispatch only | Additive: Governor wraps Coordinator |
| **SymbolGraph** — Function/class/route-level symbol nodes with SQLite | `ImportGraph` (file-level import deps only) | Additive: SymbolGraph alongside ImportGraph |
| **Incremental Updates** — Patch diff graph, not full rebuild | Full brain rebuild on every `p scan` | Additive: SQLite-backed incremental path |
| **Blast Radius v2** — Symbol-level impact analysis | File-level blast radius (`blast_radius.py`) | Phase 2 — depends on SymbolGraph |
| **Graph-Scoped Test Gen** — Tests scoped by symbol reach | Full-file test generation | Phase 2 — depends on SymbolGraph |
| **Deployment Shapes** — Docker standalone, embedded SDK, GitHub App | CLI-first | Phase 3 — deferred |

See `C:\Users\ehis\Downloads\files-5\` for full planning docs.
