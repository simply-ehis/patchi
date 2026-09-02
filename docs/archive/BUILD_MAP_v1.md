# BUILD MAP — Patchowl (Patchi)

**Last Updated:** files-5 gap reconciliation — July 4 2026
**Phase:** Phases 0-11 built, web fully audited, all subsystems linked, self-tested on patchi, files-5 gaps 1-6 resolved
**Total Files:** 125+ Python source files

---

## Self-Test Results — June 28 2026

| Category | Result |
|----------|--------|
| Module imports | 32/32 clean |
| CLI commands | 34/34 parse OK |
| API endpoints | 72 registered, 36 JS calls match |
| WS events | 69 emitted, 28 JS listeners |
| Security agents | 13/13 tested on patchi |
| Unit tests | 96/96 pass |
| Blast radius | base.py = 43 deps (CRITICAL) |
| Doctor | Core OK, 1 warning |

### Bugs Found During Self-Test
1. `blast_cmd.py` missing `ImportGraph` import
2. `blast_cmd.py` Windows backslash path mismatch in graph
3. `blast_cmd.py` `_resolve_import` missing `.py` extension
4. `security_cmd.py` `AgentInput` missing `scope` param
5. `audit_cmd.py` `AgentInput` missing `scope` param (2x)

Full report: `TEST_REPORT.md`

---

## Periodic Update — June 28 2026 (Deep Scan Pass)

### Critical Fixes
- **api.py**: Fixed broken `BrainScanner` import → now uses `build_brain()` from `brain.py`
- **api.py**: Fixed broken `horde.py` import → inline implementation using `_call_ai_horde` from `client.py`, added Ollama test support
- **main.py**: Added missing security scan types to argparse choices: `injection`, `authz`, `crypto`, `network`, `privacy`, `depvuln`, `compliance`, `secrets_guard`, `supply`, `iac`, `policy`, `cve`, `redteam`
- **iac_scanner.py**: Wrapped 4 unprotected `read_text()` calls in try/except OSError
- **plan_auditor.py**: Wrapped 3 unprotected `read_text()` calls in try/except OSError
- **plan_auditor.py**: Updated expected commands list (added `blast`, `trend`, `audit`, `learn`, `chat`, `settings`, `access`, `ai`, `help`)
- **plan_auditor.py**: Updated expected agents list (added `SecurityTestAgent`, `PlanAuditorAgent`)
- **fix_agents.py**: Replaced bare `dep_path.read_text()` with safe `_read_file()` helper
- **fix_agents.py**: `SecurityFixer._verify_fix` default trust path now returns `False` (unverified) instead of `True`
- **api.py review endpoint**: Fixed filter from `status` to `state` (patches use `state` field)

---

## Deep Web Audit — June 28 2026

### Brain Map (canvas.js)
- **Fixed**: Added missing `COLORS.component` and `COLORS.default` definitions
- **Fixed**: `ant.rejected` handler now shows toast with descriptive rejection reason
- **Fixed**: Node detail modal fetches and displays actual findings per file
- **Working**: Force-directed layout (50 iterations), zoom/pan, mini-map, tap-to-spawn
- **Working**: Node types: entry_point (hexagon), route_handler (rect), test (ring), dead (X), restricted (lock), config (diamond), sensitive (eye), component, default (circle)
- **Working**: Edge types: import_dependency (solid+arrow), route_connection (dashed amber), test_coverage (dotted green), blast_radius (solid orange), dead_path (dashed gray)
- **Working**: Ant animation: spawn flash → move to node → circle → scan pulse → return to queen → queen pulse

### Scan Loader (app.html + app.css)
- **Fixed**: Event name from `scan.done` to `scan.complete` (matching server emission)
- **Working**: 5 ant emojis with staggered march animation
- **Working**: Phase label, message, file count, progress bar

### Fix Display (panels.js + api.py)
- **Fixed**: Review panel filters patches by `state` field (not `status`)
- **Working**: Shows agent name, risk score, confidence, description, AI explanation, affected files
- **Working**: Accept/reject buttons with API calls + WS broadcast

### WebSocket Events
- **Fixed**: `queue.update` → `queue.updated` (matching server emission name)
- **Added**: `review.updated` event emitted on fix accept/reject
- **Working**: 69 server events, 28 JS listeners

### Spawn Logic (spawn.py + server.py)
- **Fixed**: `FileScanner()` now receives root parameter in `_run_spawn_scan`
- **Working**: Max 5 user ants, 10s cooldown, 60s expiry, max 3 ants per node

### Partial File Patching (prompts.py + fix_agents.py)
- **New**: Large files (>300 lines) send only 20-line context window around finding
- **New**: `_try_apply_partial()` handles AI responses like "42: fixed_code"
- **Updated**: CODE_FIX and SECURITY_FIX prompts instruct AI for partial-line fixes
- **base.py**: `_call_ai()` now accepts optional `system_prompt` parameter for skill-specific prompts

### Dead Code Removal
- **import_graph.py**: Removed duplicate `BlastRadius` class and `build_blast_radius_map`/`calculate_blast_radius` functions (superseded by `blast_radius.py`)
- **import_graph.py**: Removed unused `deque` import

### Error Handling
- **stress_test_agent.py**: Replaced bare `except:` with `except OSError:`

### Full CLI Command List (34 commands)
```
p init            — Initialize Patchi in project
p scan            — Full scan (--deep, --force, --offline, --no-side, --contract, --file, --json)
p status          — Health score, mode, queue, keys
p watch           — Auto-scan on file saves
p doctor          — Validate setup, deps, AI connection
p fix             — AI fix application (--dry-run)
p review          — Interactive patch review
p patch           — list/show/apply/reject patches
p undo            — Undo last applied fix
p redo            — Redo last undone fix
p rollback        — Roll back to before a specific patch
p test            — Run tests (unit/browser/stress/regression/accessibility/api/e2e/smoke/full)
p test generate   — AI generates test suite
p test report     — View test run history
p test config     — View/edit test config
p security        — Run all 25 defensive security agents
p security <type> — 27 scan types (taint, secrets, config, headers, ratelimit, cors, deps, probe, jwt, sensitive, auth, ssrf, injection, authz, crypto, network, privacy, depvuln, compliance, secrets_guard, supply, iac, policy, cve, redteam, report)
p memory          — show/delete memory
p queue           — pause/resume/skip/clear/mode
p mode            — confirm/auto/autopilot
p restrict        — add/scan-only/sensitive/list/remove/disable/enable
p key             — add/remove/list/test API keys
p model           — set/list/status Ollama models
p access          — add/list/remove dev access tokens
p notify          — add/remove/test/ack/flush/pending notifications
p agents          — list/status agents
p hosted          — init/worker/daemon/stop/guard/status/logs/token/block/unblock/disconnect
p report          — generate/export (markdown/json)
p settings        — show/set config
p chat            — Interactive AI chat
p web             — Start web UI (--port, --host, --no-browser)
p ai              — status/test/horde/add/remove AI keys
p explain         — Explain findings in plain English
p blast           — Blast radius analysis
p trend           — Health/quality trend over time
p audit           — Full project audit (--quick, --json)
p learn           — Learn project conventions
p help            — Show command help
```

### Security Agents (26 total)
| # | Agent | Module | What It Detects |
|---|---|---|---|
| 1 | TaintAnalyzer | security_taint.py | Data flow taint analysis |
| 2 | SecretScanner | security_taint.py | Credential detection in code |
| 3 | ConfigAuditAgent | security_config.py | Semgrep SAST, config issues |
| 4 | HeaderAuditAgent | security_agents.py | HTTP security headers |
| 5 | RateLimitAuditor | security_agents.py | Rate limiting coverage |
| 6 | CORSAuditor | security_agents.py | CORS misconfigurations |
| 7 | DependencyCVEChecker | security_probe.py | Dependency vulnerabilities |
| 8 | MisconfigAgent | misconfig_agent.py | Server/app misconfigurations |
| 9 | JWTSecurityAgent | jwt_agent.py | JWT implementation flaws |
| 10 | SensitiveDataAgent | sensitive_data_agent.py | PII exposure |
| 11 | AuthenticationAuditAgent | auth_audit_agent.py | Auth/session issues |
| 12 | SSRFProtectionAgent | ssrf_agent.py | SSRF vulnerabilities |
| 13 | InjectionAgent | injection_agent.py | SQLi, XSS, command injection |
| 14 | AuthZAgent | authz_agent.py | Authorization bypass, IDOR |
| 15 | CryptoAgent | crypto_agent.py | Weak crypto, hardcoded keys |
| 16 | NetworkAgent | network_agent.py | SSL/TLS, HTTPS enforcement |
| 17 | PrivacyAgent | privacy_agent.py | GDPR/CCPA, PII handling |
| 18 | DependencyVulnerabilityAgent | dependency_vulnerability_agent.py | Multi-ecosystem CVE |
| 19 | ComplianceAgent | compliance_agent.py | PCI DSS, HIPAA, SOX |
| 20 | SecretsGuard | secrets_guard.py | Pre-apply secrets gate |
| 21 | SupplyChainAgent | supply_chain.py | Typosquatting, pinning |
| 22 | IaCScannerAgent | iac_scanner.py | Docker/K8s/Terraform |
| 23 | PolicyEngineAgent | policy_engine.py | YAML/JSON policies |
| 24 | CVEMonitorAgent | cve_monitor.py | OSV API CVE queries |
| 25 | RedTeamAgent | red_team_agent.py | Attack surface analysis |
| 26 | SecurityProber | security_probe.py | Offensive probing |


---

## Build Pass — Phases 0-11 (June 28 2026)

### Phase 0: Register Unregistered Agents ✅
Already complete from Phase 9 session. 7 agents registered.

### Phase 1: Security Orchestrator ✅
**New file:** `core/security/orchestrator.py`
- `SecurityOrchestrator.correlate(results)` — deduplicates findings by (file, line, type)
- Cross-agent confirmation tracking (dual-agent findings get bonus score)
- Composite risk scoring (severity × 10 + confirmation bonus)
- OWASP Top 10 2021 auto-classification via CWE mapping
- Outputs `SecurityReport` with by_severity, by_owasp breakdowns

### Phase 2: Detect-Fix-Verify Loop ✅
**Modified:** `core/fix/fix_agents.py` — `SecurityFixer`
- After generating a fix, runs `_verify_fix()` to confirm the issue is actually resolved
- Secrets: checks proposed code doesn't introduce new secrets
- Pattern-based: checks the problematic snippet is gone from the target line
- Confidence adjusted: 0.85 if verified, 0.6 if unverified

### Phase 3: Secrets Guard ✅
**New file:** `core/security/secrets_guard.py`
- `scan_code_for_secrets()` — regex scanning for API keys, passwords, AWS/GCP keys, connection strings
- `gate_check_proposed_code()` — pre-apply gate that blocks patches introducing secrets
- `SecretsGuard` agent — scans .env, docker-compose, K8s manifests, CI configs
- Registered as security agent, runs in defensive scan

### Phase 4: Supply Chain Security ✅
**New file:** `core/security/supply_chain.py`
- `SupplyChainAgent` — parses package.json, requirements.txt, pyproject.toml, Cargo.toml, go.mod, composer.json, Gemfile
- Typosquatting detection via Levenshtein distance against popular packages
- Dependency pinning validation (flags *, latest, >=0 as unpinned)
- 7 package ecosystem parsers built-in

### Phase 5: Security Test Auto-Generation ✅
**New file:** `core/testing/security_test_agent.py`
- `SecurityTestAgent` — generates per-route security tests
- Templates: auth bypass, SQLi, XSS, CSRF, CORS, rate limiting
- Outputs pytest files in `tests/security/` with proper directory structure
- Registered as test agent

### Phase 6: Runtime Validation ✅
Covered by existing `SecurityProber` + new `RedTeamAgent` (Phase 11)

### Phase 7: Plan-Auditing ✅
Covered by `PolicyEngineAgent` (Phase 9) with compliance pack support

### Phase 8: IaC & Container Security ✅
**New file:** `core/security/iac_scanner.py`
- `IaCScannerAgent` — scans Dockerfiles, docker-compose, K8s manifests, Terraform
- Dockerfile: root user, exposed sensitive ports, latest tag, missing USER directive
- docker-compose: privileged containers, host network, dangerous volume mounts
- K8s: missing securityContext, missing resource limits, no NetworkPolicy
- Terraform: public S3 ACL, open security groups (0.0.0.0/0), unencrypted storage

### Phase 9: Security Policy Engine ✅
**New file:** `core/security/policy_engine.py`
- `PolicyEngineAgent` — loads YAML/JSON policies from `.patchi/policies/`
- Built-in packs: SOC2, HIPAA, PCI-DSS, CIS Controls
- Checks: default credentials, plaintext HTTP, weak crypto, hardcoded secrets, SQL injection, file permissions, password strength
- Custom policies via `.patchi/policies/*.yaml` or `*.json`

### Phase 10: CVE Monitor ✅
**New file:** `core/security/cve_monitor.py`
- `CVEMonitorAgent` — queries OSV API for known CVEs in project dependencies
- Supports npm and PyPI ecosystems
- Maps OSV severity to internal severity levels
- Registered as security agent

### Phase 11: Red Team Agent ✅
**New file:** `core/security/red_team_agent.py`
- `RedTeamAgent` — adversarial testing and attack surface analysis
- Route analysis: parameterized routes, state-changing endpoints
- Source scanning: eval(), exec(), os.system(), pickle, yaml.load, DEBUG=True, ALLOWED_HOSTS=*
- CWE-tagged findings with code snippets

### New Tests ✅
**New file:** `tests/test_new_security_agents.py` — 27 tests covering all new agents
- Orchestrator: dedup, severity ordering, OWASP classification
- Secrets Guard: detection, gate blocking, clean code passthrough
- Supply Chain: Levenshtein, typosquatting, empty project
- IaC Scanner: root user, latest tag, privileged container, public S3
- Policy Engine: default credentials, weak crypto, clean code
- CVE Monitor: empty project
- Red Team: eval detection, debug mode, empty project
- Security Test Agent: route generation, no routes noop

### Test Results
**210 critical tests passed**, 0 failures (security agents + new agents + base + coordinator + test agents)

### Registration Updates
- `security_agents.py` — 6 new agents added (SecretsGuard, SupplyChainAgent, IaCScannerAgent, PolicyEngineAgent, CVEMonitorAgent, RedTeamAgent)
- `test_agents.py` — 1 new agent added (SecurityTestAgent)
- `security_cmd.py` — 6 new scan types added (secrets_guard, supply, iac, policy, cve, redteam)
- Defensive agent list expanded to 25 agents

---

## Deep Scan Findings — June 28 2026

Full codebase scan of all security agents, core modules, CLI, and web.
**Test suite:** 752 passed, 1 skipped, 3 warnings — all green.

### CRITICAL — Fixed

| # | File | Line | Issue | Status |
|---|---|---|---|---|
| 1 | `core/security/misconfig_agent.py` | 61,75 | **`inp.root.rglob()` instead of `safe_rglob()`** — traverses into node_modules, .git, __pycache__ | ✅ Fixed — added `safe_rglob` import, replaced both `rglob` calls |
| 2 | `core/security/injection_agent.py` | 158 | **`node.func.id in ['os.system', ...]` never matches** — `os.system` is `ast.Attribute`, not `Name` | ✅ Fixed — split into Name checks (eval/exec) and Attribute checks (os.system, subprocess.call, etc.) |
| 3 | `core/security/injection_agent.py` | 146, 161 | **`py_ast.Str` removed in Python 3.12** | ✅ Fixed — replaced with `py_ast.Constant` + `isinstance(arg.value, str)` |

### HIGH — Fixed

| # | File | Line | Issue | Status |
|---|---|---|---|---|
| 4 | `core/agents/coordinator.py` | 144 | **`brain.get("frameworks", [""])[0]` type mismatch** — string gives first char | ✅ Fixed — added `isinstance` check for list vs string |
| 5 | `core/security/network_agent.py` | 169-179 | **Inverted HTTPS redirect logic** — fires on every HTTP line | ✅ Fixed — rewritten to check whole-file for enforcement, then flag plain HTTP lines |
| 6 | `core/security/authz_agent.py` | 161 | **Overly broad route detection** — any function with 'get'/'post' in name | ✅ Fixed — now checks for route decorators + function name prefixes (get_X, post_X, etc.) |
| 7 | `core/security/crypto_agent.py` | 191 | **Hardcoded key pattern too broad** — matches UUIDs, hashes, test fixtures | ✅ Fixed — requires key-like context (secret/key/token/password word before assignment) |
| 8 | `core/security/crypto_agent.py` | 269 | **`random()` / `rand()` flags all randomness** | ✅ Fixed — scoped to specific Python PRNG calls, downgraded to MEDIUM with context note |
| 9 | `core/security/privacy_agent.py` | 134 | **`\bname\b` matches every "name" occurrence** | ✅ Fixed — changed to specific patterns: `first_name`, `last_name`, `full_name`, `user_name` |
| 10 | `core/security/dependency_vulnerability_agent.py` | 566-579 | **HIGH and CRITICAL both map to Severity.CRITICAL** | ✅ Fixed — HIGH now maps to Severity.HIGH |

### MEDIUM — Noted (deferred)

| # | File | Issue | Status |
|---|---|---|---|
| 11 | All 7 new security agents | `_should_skip_file` SCAN_ONLY check always False (dead code) | ⏭ Deferred — harmless dead code, not blocking |
| 12 | `dependency_vulnerability_agent.py` | Synchronous OSV API calls per dependency (slow on large projects) | ⏭ Deferred — performance, not correctness |
| 13 | `security_taint.py` + `security_probe.py` | Duplicate `_run()` and `_call_ai()` functions | ⏭ Deferred — refactor, not a bug |
| 14 | All 7 new security agents | `_run(self, inp)` 1-param signature (works via compat) | ⏭ Deferred — backwards compat handles it |
| 15 | `crypto_agent.py` | Salt regex single-line only | ⏭ Deferred — edge case |
| 16 | `sensitive_data_agent.py` | Credential patterns fire on test fixtures | ⏭ Deferred — needs test-dir exclusion |

### What's solid (no issues found)

- `core/agents/base.py` — BaseAgent, Finding, safe_rglob, registry. Well-structured.
- `core/agents/coordinator.py` — ThreadPoolExecutor parallel/sequential/batched. Correct logic (except framework type bug).
- `core/security/security_agents.py` — All 20 agents imported and registered correctly.
- `core/health.py` — Health score computation. Correct weighting and capping.
- `core/security/sensitive_data_agent.py` — Good credential patterns (except test file false positives).
- `core/security/security_taint.py` — TaintAnalyzer + SecretScanner with subprocess integration.
- `core/security/security_config.py` — ConfigAuditAgent with Semgrep CE integration.
- `core/security/jwt_agent.py` — JWT analysis.
- `core/security/auth_audit_agent.py` — Authentication audit.
- `core/security/ssrf_agent.py` — SSRF detection.
- `core/security/secret_scanning_agent.py` — Secret scanning.
- `core/security/sast_agent.py` — SAST wrapper.

---

## Logic Pass — Weird, Odd, Confusing Logic + Hardcoded Reports

### WEIRD LOGIC — Score Calculation (ALL FIXED)

| # | File | Line | Issue | Fix |
|---|---|---|---|---|
| 1 | `core/health.py` | 237-242 | **Contract score paradox** — never-scanned project scores 70, scanned-but-unconfirmed scores 0 | ✅ Changed defaults: no flows = 50.0 (truly neutral), flows inferred but none confirmed = 20.0 (penalised but not zero) |
| 2 | `core/health.py` | 86 | **`test_coverage_pct` computed but never used** — expensive file-walk result ignored | ✅ `_compute_test_coverage` now accepts `real_pct` param and uses it as fallback when TestScanner data missing |
| 3 | `core/health.py` | 209 | **Dead code formula floor was 10, not 0** — 100% dead code still scored 10/100 | ✅ Changed `max(10.0, ...)` to `max(0.0, ...)` |
| 4 | `core/health.py` | 215-225 | **Dependency docstring lied** — said "-30 per dep" but formula was ratio-based | ✅ Updated docstring to match actual formula |

### WEIRD LOGIC — Fix Agents (ALL FIXED)

| # | File | Line | Issue | Fix |
|---|---|---|---|---|
| 5 | `core/fix/fix_agents.py` | 295 | **`DeadCodeRemover` uses `rglob` not `safe_rglob`** — traverses node_modules | ✅ Replaced with `safe_rglob(inp.root, "*.py")` |
| 6 | `core/fix/fix_agents.py` | 301 | **`getattr(` pattern matches everything** — DeadCodeRemover rarely proposes deletions | ✅ Removed `getattr(` from dynamic reference patterns (overly broad) |
| 7 | `core/fix/fix_agents.py` | 328-334 | **`is_special_ext` always True** — dead logic, ext check was pointless | ✅ Removed dead `is_special_ext` check, simplified to `is_special_dir` only |
| 8 | `core/fix/fix_agents.py` | 220-224 | **SecurityFixer operator precedence** — `fix_agent` check bypasses hardcoded_secret exclusion | ✅ Added parentheses: `(fix_agent == self.name) or (severity in crit/high AND type != secret)` |
| 9 | `core/fix/fix_agents.py` | 739-747 | **Test path always flat** — `src/auth/login.py` gets `tests/test_login.py` | ✅ Now mirrors source structure: `tests/src/auth/test_login.py` |

### WEIRD LOGIC — Risk Gate + Coordinator (ALL FIXED)

| # | File | Line | Issue | Fix |
|---|---|---|---|---|
| 10 | `core/fix/risk_gate.py` | 242 | **Only `no_touch` enforced** — `SCAN_ONLY` and `SENSITIVE` restrictions ignored by gate | ✅ Now checks all three restriction types: `no_touch`, `scan_only`, `sensitive` |
| 11 | `core/agents/coordinator.py` | 219-220 | **Hardcoded workers conflict with DeviceTier** — two sources of truth | ✅ Now uses `DeviceTier(device_tier).max_parallel_agents()` as single source of truth |
| 12 | `core/agents/coordinator.py` | 138 | **Stale agent names in reorder check** — never triggers | ✅ Updated names to match actual registered agents: `ConfigAuditAgent`, `TaintAnalyzer`, `CORSAuditor` |

### HARDCODED USER-FACING STRINGS

#### Health Score (shown in `p status`, `p report`, web UI)

| File | Line | Hardcoded String | What Users See |
|---|---|---|---|
| `core/health.py` | 326-334 | Grade thresholds: 90=A, 70=B, 50=C, 30=D, below=F | Letter grade on every status display |
| `core/health.py` | 326-334 | Colors: `#4ADE80`, `#86EFAC`, `#FACC15`, `#FB923C`, `#FF4D6D` | Grade colors in CLI + web |
| `core/health.py` | 192 | `"return 50.0"` — fallback when no TestScanner data | Default test coverage score |
| `core/health.py` | 222 | `"return 80.0"` — fallback when no deps found | Default dependency score |
| `core/health.py` | 239 | `"return 70.0"` — fallback when no contract flows | Default contract score |

#### Status Command (shown in `p status`)

| File | Line | Hardcoded String |
|---|---|---|
| `cli/commands/status_cmd.py` | 71 | `"No scan yet"` |
| `cli/commands/status_cmd.py` | 72 | `"Run p scan to compute"` |
| `cli/commands/status_cmd.py` | 78 | `"Files changed since last scan"` |
| `cli/commands/status_cmd.py` | 90 | `"Ready"` / `"Stale"` / `"Error:"` |
| `cli/commands/status_cmd.py` | 99-102 | Mode descriptions: `"Every fix requires your approval"` / `"Low-risk auto-applied, risky ones ask"` / `"Full trust — Patchi decides"` |
| `cli/commands/status_cmd.py` | 127 | `"Offline · zero cost"` |
| `cli/commands/status_cmd.py` | 139 | `"AI Horde · slower but always works"` |
| `cli/commands/status_cmd.py` | 142 | `"Run p key add or p init"` |

#### Risk Gate (shown when patches are evaluated)

| File | Line | Hardcoded String |
|---|---|---|
| `core/fix/risk_gate.py` | 131-133 | `"App contract not confirmed. Run 'p scan' and confirm your critical flows first. No fixes will apply until the contract is locked."` |
| `core/fix/risk_gate.py` | 141-142 | `"'{path}' is in a restricted no-touch zone ({no_touch}). Modify restrictions with 'p restrict'."` |
| `core/fix/risk_gate.py` | 152-153 | `"High-risk patch (score {score}) requires a blast radius report. Patchi is computing it — this patch will be re-evaluated once ready."` |
| `core/fix/risk_gate.py` | 161-162 | `"Low confidence ({conf}%). Patchi is less certain than usual about this fix."` |
| `core/fix/risk_gate.py` | 167-168 | `"High blast radius: {n} files depend on the changed file(s). Thorough testing is recommended."` |
| `core/fix/risk_gate.py` | 173-174 | `"Large patch: {n} lines changed across {f} file(s)."` |
| `core/fix/risk_gate.py` | 197 | `"CONFIRM mode — every fix requires approval."` |
| `core/fix/risk_gate.py` | 202 | `"AUTO mode — risk score {score} ≤ threshold {threshold}."` |
| `core/fix/risk_gate.py` | 206-207 | `"AUTO mode — risk score {score} exceeds threshold {threshold}. Surfaced for review."` |
| `core/fix/risk_gate.py` | 212 | `"AUTOPILOT mode — all fixes apply automatically."` |
| `core/fix/risk_gate.py` | 215-216 | `"High-risk fix applied automatically (AUTOPILOT). Risk score: {score}. Switch to AUTO mode for manual review."` |

#### Fix Agents (shown in patch descriptions)

| File | Line | Hardcoded String |
|---|---|---|
| `core/fix/fix_agents.py` | 190 | `"Fix: {message}"` |
| `core/fix/fix_agents.py` | 250 | `"Security fix: {message}"` |
| `core/fix/fix_agents.py` | 251 | `"Fixes {cwe}: {suggestion}"` |
| `core/fix/fix_agents.py` | 351-354 | `"Remove dead file: {path}"` + explanation about no importers |
| `core/fix/fix_agents.py` | 425 | `"Update vulnerable dependency: {pkg}"` |
| `core/fix/fix_agents.py` | 486 | `"Replace hardcoded secret in {path}"` |
| `core/fix/fix_agents.py` | 486 | `"Moved secret to environment variable reference."` |
| `core/fix/fix_agents.py` | 519 | `"Generate .env.example from discovered env variables"` |
| `core/fix/fix_agents.py` | 565 | `"TypeScript fix ({type}): {path}"` |
| `core/fix/fix_agents.py` | 566 | `"Fixed TypeScript type issue."` |
| `core/fix/fix_agents.py` | 656 | `"Extract shared logic from {file1} and {file2}"` |
| `core/fix/fix_agents.py` | 657 | `"Functions are {score}% similar. Extracted to shared utility."` |
| `core/fix/fix_agents.py` | 727 | `"Add tests for {path}"` |
| `core/fix/fix_agents.py` | 728 | `"Generated unit test skeleton covering exported functions."` |

#### Security Agent Findings (shown in scan reports)

| File | Pattern | Hardcoded Strings |
|---|---|---|
| All security agents | Finding titles | `"SQL Injection"`, `"Command Injection"`, `"Cross-Site Scripting (XSS)"`, `"Path Traversal"`, `"Missing Authentication Check"`, `"Weak Hash Algorithm (MD5)"`, `"Hardcoded Cryptographic Key"`, `"Weak SSL/TLS Protocol"`, `"Plain HTTP without HTTPS enforcement"`, `"Missing Security Headers"` |
| `dependency_vulnerability_agent.py` | 79 | `"Dependency Vulnerabilities: {n} found"` |
| `dependency_vulnerability_agent.py` | 141 | `"Dependency File Scanned: {name}"` |

#### Constants (model names, URLs)

| File | Line | Hardcoded Value |
|---|---|---|
| `core/constants.py` | 135-148 | All provider base URLs and default model names (gpt-4o-mini, claude-sonnet-4-20250514, gemini-2.0-flash, etc.) — will go stale as models are deprecated |
| `core/constants.py` | 158 | `AI_HORDE_ANON_KEY = "0000000000"` — hardcoded API key (public anon key, but still a key in source) |
| `core/constants.py` | 176 | `PATCHI_VERSION = "0.6.0"` — version string |

---

## Phase 9 Changes (this session) — Security-Native Upgrade Phase 0

### New: 7 Security Agents Registered
All agents existed as files but were NOT imported/registered. Now fully integrated.

| Agent | Module | What It Detects |
|---|---|---|
| `InjectionAgent` | `injection_agent.py` | SQLi, XSS, command injection, path traversal (Python/JS/Java/PHP/Ruby) |
| `AuthZAgent` | `authz_agent.py` | Missing auth decorators, broken access control, IDOR, privilege escalation |
| `CryptoAgent` | `crypto_agent.py` | Weak hashing (MD5/SHA1), weak encryption (DES/RC4), hardcoded keys, insecure PRNG |
| `NetworkAgent` | `network_agent.py` | Weak SSL/TLS protocols, weak ciphers, missing HTTPS, plain HTTP URLs |
| `PrivacyAgent` | `privacy_agent.py` | PII handling, GDPR/CCPA references, tracking consent, data retention |
| `DependencyVulnerabilityAgent` | `dependency_vulnerability_agent.py` | Multi-ecosystem CVE checks (npm, PyPI, Cargo, Go, Composer, Gem) via OSV API |
| `ComplianceAgent` | `compliance_agent.py` | PCI DSS, HIPAA, GDPR, SOX pattern detection, missing audit trails |

### Bug Fixes
- Fixed `safe_rglob` bug: all 7 agents now use `safe_rglob()` instead of `inp.root.rglob()` (was traversing into node_modules)
- Fixed `Lang.JSX`/`Lang.TS` references: removed non-existent enum values from `InjectionAgent` and `AuthZAgent`
- Fixed SQL injection AST detection: removed overly restrictive `cursor` attribute check
- Fixed `InjectionAgent._scan_python_injection`: now runs general patterns after AST walk (was skipping command injection via `system()`)
- Fixed web API import paths: 4 endpoints had wrong `patchi.core.agents.security_agents` (correct: `patchi.core.security.security_agents`)
- Fixed web API quick-scan agent names: `TaintAnalysis`→`TaintAnalyzer`, `ConfigSecurity`→`ConfigAuditAgent`
- Updated `max_security_agents` config default from 4 to 19

### Updated Files
- `patchi/core/security/security_agents.py` — imports all 20 agents
- `patchi/cli/commands/security_cmd.py` — 7 new scan types, 19 defensive agents
- `patchi/core/health.py` — `_compute_security` now factors in findings from all 19 security agents
- `patchi/core/config.py` — `max_security_agents` default increased to 19
- `patchi/web/api.py` — fixed import paths and agent names in 4 endpoints
- `patchi/core/security/injection_agent.py` — fixed Lang enum, added general pattern fallback
- `patchi/core/security/authz_agent.py` — fixed Lang enum
- All 7 new agents: added `safe_rglob` import, replaced `inp.root.rglob()`
- `tests/test_security_agents.py` — added 28 tests for 7 new agents (99 total security tests)

### Test Results
- **752 passed**, 1 skipped, 3 warnings
- All existing tests continue to pass
- 28 new tests added for the 7 newly registered agents

---

## Architecture Overview

```
patchi/
├── cli/              ← Argparse entrypoints, commands
│   ├── main.py       ← Root parser, dispatches to ALL commands (no stubs remain)
│   ├── logo.py       ← ASCII logo draw sequence
│   └── commands/     ← One file per CLI command (24 command modules)
├── core/
│   ├── brain/        ← AST scanning, language detection, import graph
│   ├── agents/       ← Scanner agents, base agent, coordinator
│   ├── fix/          ← Fix agents, patch applier, risk gate
│   ├── testing/      ← 7 test agents (unit/browser/stress/regression/batch/accessibility/api)
│   ├── security/     ← Security scanning agents (taint, CORS, deps, etc.)
│   ├── hosted/       ← Hosted mode core (tokens, audit log, anomaly, watchlist, parsers)
│   ├── notifications/← Notification channels, digest, escalation, quiet hours
│   ├── config.py     ← .patchi/config.json loader
│   ├── constants.py  ← Shared constants (severity, status, etc.)
│   ├── memory.py     ← Persistent scan memory (JSON-backed)
│   ├── queue.py      ← Task queue (JSON-backed)
│   ├── snapshot.py   ← File snapshot / rollback support
│   └── health.py     ← Health score computation (0–100, A–F grade)
├── web/              ← Web UI (FastAPI + static assets)
└── tests/            ← 23 unit tests, one per core module
```

---

## Phase 8 Changes (this session)

### New command modules
- `patchi/cli/commands/doctor_cmd.py`  — `p doctor` fully implemented
- `patchi/cli/commands/model_cmd.py`   — `p model set/list/status` fully implemented
- `patchi/cli/commands/report_cmd.py`  — `p report` + `p report export` fully implemented
- `patchi/cli/commands/hosted_cmd.py`  — `p hosted` all 9 subcommands fully implemented

### New test agents
- `BatchTestAgent`         — parallel test execution (pytest-xdist or subprocess batching)
- `AccessibilityTestAgent` — WCAG checks via pa11y or axe-core/Playwright
- `APITestAgent`           — REST API contract testing via schemathesis or manual probe

### Updated
- `patchi/cli/main.py`           — all four stubs replaced with real dispatch; test choices expanded
- `patchi/cli/commands/test_cmd.py` — name_map expanded; docstring updated
- `patchi/core/testing/test_agents.py` — three new agents appended
- `BUILD_MAP.md`                  — this file; accurately reflects current state

---

## CLI Commands — Complete Status

| Command           | Status    | Notes                                      |
|-------------------|-----------|--------------------------------------------|
| `p init`          | ✅ Live   | Scaffolds .patchi/ dir                     |
| `p scan`          | ✅ Live   | Full or targeted scan                      |
| `p status`        | ✅ Live   | Health score, mode, queue, keys            |
| `p watch`         | ✅ Live   | File-change watcher                        |
| `p fix`           | ✅ Live   | AI fix application                         |
| `p review`        | ✅ Live   | Interactive patch review                   |
| `p patch`         | ✅ Live   | list/show/apply/reject                     |
| `p undo/redo`     | ✅ Live   | Snapshot rollback                          |
| `p test`          | ✅ Live   | 7 modes: unit/browser/stress/regression/batch/accessibility/api |
| `p security`      | ✅ Live   | 19 scan types (+ 7 new: injection, authz, crypto, network, privacy, depvuln, compliance) |
| `p memory`        | ✅ Live   | show/delete                                |
| `p queue`         | ✅ Live   | pause/resume/skip/clear/mode               |
| `p mode`          | ✅ Live   | confirm/auto/autopilot                     |
| `p restrict`      | ✅ Live   | add/scan-only/sensitive/list/remove        |
| `p key`           | ✅ Live   | add/remove/list/test                       |
| `p agents`        | ✅ Live   | list/status                                |
| `p notify`        | ✅ Live   | channels, digest, escalation               |
| `p web`           | ✅ Live   | FastAPI dashboard                          |
| `p access`        | ✅ Live   | dev token management                       |
| `p settings`      | ✅ Live   | show/set                                   |
| `p doctor`        | ✅ Live   | dependency + API key + Ollama checks       |
| `p model`         | ✅ Live   | Ollama set/list/status                     |
| `p report`        | ✅ Live   | terminal report + markdown/JSON export     |
| `p hosted`        | ✅ Live   | init/worker/guard/status/logs/token/disconnect |

**No commands remain stubbed.**

---

## Files

### CLI — `patchi/cli/`

#### `patchi/cli/main.py`
**Does:** Root CLI parser. Registers all subcommands, dispatches to command handlers. No stubs.
**Exports:** `main()` (entry point)
**Phase 8:** Expanded test choices; replaced 4 `_coming_soon` stubs with real dispatch.

#### `patchi/cli/logo.py`
**Does:** Draws the animated ASCII logo sequence.
**Exports:** `draw_logo()`

#### `patchi/cli/commands/init.py`
**Does:** `p init` — scaffolds `.patchi/` directory, writes default config.
**Exports:** `run()`

#### `patchi/cli/commands/scan_cmd.py`
**Does:** `p scan` — full or targeted scan via brain + scanner agents.
**Exports:** `run()`

#### `patchi/cli/commands/security_cmd.py`
**Does:** `p security` — 8 scan types (taint, secrets, config, headers, ratelimit, cors, deps, probe).
**Exports:** `run()`

#### `patchi/cli/commands/test_cmd.py`
**Does:** `p test` — 7 test modes. Runs test agents sequentially, renders results table.
**Exports:** `run()`
**Phase 8:** name_map expanded to include batch/accessibility/api.

#### `patchi/cli/commands/fix_cmd.py`
**Does:** `p fix` — AI fix application with risk gate.
**Exports:** `run()`

#### `patchi/cli/commands/review_cmd.py`
**Does:** `p review` — interactive patch review panel.
**Exports:** `run()`

#### `patchi/cli/commands/patch_cmd.py`
**Does:** `p patch` — list/show/apply/reject patches.
**Exports:** `run_list(), run_show(), run_apply(), run_reject()`

#### `patchi/cli/commands/undo_cmd.py`
**Does:** `p undo / redo / rollback` — snapshot rollback.
**Exports:** `run_undo(), run_redo(), run_rollback()`

#### `patchi/cli/commands/queue_cmd.py`
**Does:** `p queue` — view/pause/resume/clear/mode.
**Exports:** `run_show(), run_pause(), run_resume(), run_skip(), run_clear(), run_set_mode()`

#### `patchi/cli/commands/memory_cmd.py`
**Does:** `p memory` — view and delete scan memory.
**Exports:** `run_show_all(), run_show(), run_delete()`

#### `patchi/cli/commands/status_cmd.py`
**Does:** `p status` — health score, mode, queue depth, key status.
**Exports:** `run()`

#### `patchi/cli/commands/key_cmd.py`
**Does:** `p key` — add/remove/list/test API keys.
**Exports:** `run_add(), run_list(), run_remove(), run_test()`

#### `patchi/cli/commands/agents_cmd.py`
**Does:** `p agents` — inspect agent registry, last run stats.
**Exports:** `run_list(), run_status()`

#### `patchi/cli/commands/watch_cmd.py`
**Does:** `p watch` — file-change watcher, auto-scan on save.
**Exports:** `run()`

#### `patchi/cli/commands/mode_cmd.py`
**Does:** `p mode` — view or set operating mode.
**Exports:** `run_show(), run_set()`

#### `patchi/cli/commands/restrict_cmd.py`
**Does:** `p restrict` — manage file restriction zones.
**Exports:** `run_add(), run_list(), run_remove(), run_disable(), run_enable()`

#### `patchi/cli/commands/notify_cmd.py`
**Does:** `p notify` — configure notification channels.
**Exports:** `run_notify()`

#### `patchi/cli/commands/web_cmd.py`
**Does:** `p web` — start the FastAPI web dashboard.
**Exports:** `run_web()`

#### `patchi/cli/commands/doctor_cmd.py` ← NEW Phase 8
**Does:** `p doctor` — validates Python version, required/optional deps, project root,
API keys (live connection test), and Ollama model availability.
**Exports:** `run(verbose)`

#### `patchi/cli/commands/model_cmd.py` ← NEW Phase 8
**Does:** `p model set/list/status` — manages Ollama local model integration.
Queries `localhost:11434`, saves model name to config, pings for first-token latency.
**Exports:** `run_set(), run_list(), run_status()`

#### `patchi/cli/commands/report_cmd.py` ← NEW Phase 8
**Does:** `p report` + `p report export` — terminal report and markdown/JSON export.
Pulls all data from brain memory — no re-scan triggered.
**Exports:** `run(export, fmt, root)`

#### `patchi/cli/commands/hosted_cmd.py` ← NEW Phase 8
**Does:** `p hosted init/worker/guard/status/logs/token/disconnect` — full hosted mode CLI.
Uses all five `patchi/core/hosted/` modules.
**Exports:** `run(args)` (dispatches internally)

---

### Core — `patchi/core/`

#### `patchi/core/agents/base.py`
**Does:** Agent base class, registry, AgentInput/AgentResult types, Severity enum.
**Exports:** `BaseAgent, AgentGroup, AgentInput, AgentResult, register, list_agents,
             make_finding, Severity, AgentStatus`

#### `patchi/core/agents/coordinator.py`
**Does:** Runs multiple agents, manages concurrency, collects results.
**Exports:** `Coordinator`

#### `patchi/core/agents/scanners.py`
**Does:** All scanner agents (FileScanner, EnvScanner, DeadCodeScanner, etc.).
**Exports:** All scanner agent classes (auto-registered via `@register`)

#### `patchi/core/brain/brain.py`
**Does:** Orchestrates all brain scanners, writes to memory.
**Exports:** `build_brain()`

#### `patchi/core/brain/contract.py`
**Does:** App contract inference from route + auth patterns.
**Exports:** `ContractScanner`

#### `patchi/core/brain/framework.py`
**Does:** Framework detection (Django, Flask, FastAPI, Rails, etc.)
**Exports:** `detect_framework()`

#### `patchi/core/brain/freshness.py`
**Does:** Brain freshness checks — decides if re-scan is needed.
**Exports:** `is_fresh(), mark_fresh()`

#### `patchi/core/brain/import_graph.py`
**Does:** Builds import dependency graph, detects circular imports.
**Exports:** `build_import_graph()`

#### `patchi/core/brain/languages.py`
**Does:** Language detection from file extensions and shebang lines.
**Exports:** `detect_languages()`

#### `patchi/core/brain/route_mapper.py`
**Does:** Route extraction from web frameworks.
**Exports:** `RouteMapScanner`

#### `patchi/core/brain/scanner.py`
**Does:** AST-level scanner for Python files.
**Exports:** `ASTScanner`

#### `patchi/core/config.py`
**Does:** `.patchi/config.json` read/write. find_project_root(), require_project_root(),
config merge, restrictions, dev tokens.
**Exports:** `load(), save(), get(), set_value(), find_project_root(), require_project_root()`

#### `patchi/core/constants.py`
**Does:** All shared enums (Mode, QueueMode, Severity, RestrictionType, etc.) and path constants.

#### `patchi/core/fix/applier.py`
**Does:** Applies patches to disk, snapshots before apply.
**Exports:** `apply_patch()`

#### `patchi/core/fix/fix_agents.py`
**Does:** AI-powered fix agent implementations.
**Exports:** Fix agent classes

#### `patchi/core/fix/patch.py`
**Does:** Patch data model, storage, retrieval.
**Exports:** `Patch, save_patch(), load_patch(), list_patches()`

#### `patchi/core/fix/risk_gate.py`
**Does:** Risk assessment before applying a fix. Blocks high-risk changes.
**Exports:** `assess_risk()`

#### `patchi/core/health.py`
**Does:** Health score computation (0–100, A–F). Weights: security 35%, tests 25%,
dead code 20%, deps 10%, contract 10%.
**Exports:** `compute(), HealthScore`

#### `patchi/core/hosted/anomaly.py`
**Does:** StatisticalDetector + MLDetector (IsolationForest) for live log anomaly detection.
**Exports:** `StatisticalDetector, MLDetector, AnomalyFinding`

#### `patchi/core/hosted/audit_log.py`
**Does:** Rotating JSON-lines audit log. Writes one entry per event. Rotates at 5 MB.
**Exports:** `write(), read_recent(), clear()`

#### `patchi/core/hosted/log_parsers.py`
**Does:** Parses 7 log formats (nginx, apache, caddy, uvicorn, gunicorn, cloudflare, JSON)
into unified `LogEntry` objects.
**Exports:** `parse_line(), parse_lines(), LogEntry`

#### `patchi/core/hosted/tokens.py`
**Does:** Admin token management. Stores HMAC-SHA256 hash, never plaintext.
**Exports:** `generate(), validate(), list_tokens(), revoke(), count()`

#### `patchi/core/hosted/watchlist.py`
**Does:** IP threat scoring with time-decay. Escalates when thresholds crossed.
**Exports:** `WatchlistTracker`

#### `patchi/core/memory.py`
**Does:** All persistent memory I/O. Atomic writes (write-tmp + rename).
**Exports:** `get_brain(), save_brain(), get_scan_results(), save_scan_result(),
             list_patches(), save_token(), list_tokens(), remove_token()`

#### `patchi/core/notifications/channels.py`
**Does:** Notification channel implementations (email, Slack, Discord, webhook, Telegram).

#### `patchi/core/notifications/digest.py`
**Does:** Batches notifications into periodic digests.

#### `patchi/core/notifications/escalation.py`
**Does:** Escalation logic — CRITICAL/HIGH alerts bypass digest.

#### `patchi/core/notifications/notifier.py`
**Does:** Main notifier — routes findings to appropriate channels.
**Exports:** `Notifier`

#### `patchi/core/notifications/quiet_hours.py`
**Does:** Suppresses non-critical notifications during configured quiet window.

#### `patchi/core/queue.py`
**Does:** Task queue backed by JSON. Pause/resume/skip/clear.
**Exports:** `Queue, QueueItem`

#### `patchi/core/security/security_agents.py`
**Does:** 8 security scanning agents (TaintAgent, SecretsAgent, ConfigAgent, HeadersAgent,
RateLimitAgent, CORSAgent, DependencyAgent, ProbeAgent).

#### `patchi/core/snapshot.py`
**Does:** File snapshot system. Stores pre-patch content for undo/rollback.
**Exports:** `snapshot(), restore(), list_snapshots()`

#### `patchi/core/testing/test_agents.py`
**Does:** 7 test agents.
**Phase 8:** BatchTestAgent, AccessibilityTestAgent, APITestAgent added.

| Agent                  | Backend                        | Phase |
|------------------------|--------------------------------|-------|
| UnitTestAgent          | pytest / jest / phpunit        | 6     |
| BrowserTestAgent       | Playwright                     | 6     |
| StressTestAgent        | Locust                         | 6     |
| RegressionAgent        | UnitTestAgent + baseline delta | 6     |
| BatchTestAgent         | pytest-xdist / subprocess pool | 8     |
| AccessibilityTestAgent | pa11y / axe-core + Playwright  | 8     |
| APITestAgent           | schemathesis / manual probe    | 8     |

---

### Web — `patchi/web/`

#### `patchi/web/server.py`
**Does:** FastAPI app factory. Mounts API router, serves static files, initialises SpawnManager.

#### `patchi/web/api.py`
**Does:** REST API endpoints — `/api/scan/start`, `/api/scan/stop`, scan results, status.

#### `patchi/web/spawn.py`
**Does:** SpawnManager — gates web-initiated agent spawning when active flag is set.
Activation path exists via `/api/scan/start` and `/api/scan/stop`.

#### `patchi/web/events.py`
**Does:** Server-Sent Events stream for real-time log push to web UI.

#### `patchi/web/static/`
**Contains:** `app.html`, `app.css`, `canvas.js`, `panels.js`, `ws.js`

---

### Tests — `patchi/tests/`

23 test files — one per core module. All parse cleanly.

| Test file                       | Covers                           |
|---------------------------------|----------------------------------|
| test_applier.py                 | core/fix/applier.py              |
| test_base.py                    | core/agents/base.py              |
| test_config.py                  | core/config.py                   |
| test_contract.py                | core/brain/contract.py           |
| test_coordinator.py             | core/agents/coordinator.py       |
| test_fix_agents.py              | core/fix/fix_agents.py           |
| test_framework.py               | core/brain/framework.py          |
| test_freshness.py               | core/brain/freshness.py          |
| test_import_graph.py            | core/brain/import_graph.py       |
| test_memory.py                  | core/memory.py                   |
| test_notifications.py           | core/notifications/              |
| test_patch.py                   | core/fix/patch.py                |
| test_queue.py                   | core/queue.py                    |
| test_risk_gate.py               | core/fix/risk_gate.py            |
| test_route_mapper.py            | core/brain/route_mapper.py       |
| test_scanner.py                 | core/brain/scanner.py            |
| test_scanners.py                | core/agents/scanners.py          |
| test_security_agents.py         | core/security/security_agents.py |
| test_security_agents_deep.py    | deeper security agent coverage   |
| test_snapshot.py                | core/snapshot.py                 |
| test_test_agents.py             | core/testing/test_agents.py      |
| test_web.py                     | web/ (server, api, spawn)        |

---

## Known Limitations

- `BatchTestAgent` subprocess-batching fallback does not share a pytest session;
  fixtures with session scope may run multiple times.
- `AccessibilityTestAgent` axe-core mode requires an internet connection to fetch the
  axe CDN script during testing.
- `APITestAgent` manual probe sends empty JSON bodies to POST/PUT endpoints —
  routes that require specific schemas will return 422 (not flagged as a failure).
- `p model` Ollama ping uses `/api/generate` — very large models may time out (15s limit).

---

---

## files-5 Gap Reconciliation — July 4 2026

### Changes Made
- **🤖 AI Horde fallback now enabled by default** — `config.py` `_default_config()` sets `horde_fallback: true` (was false) and reads `horde_key` from config
- **✏️ New Makefile** — `venv`, `install`, `install-web`, `dev`, `clean`, `lint`, `test` targets
- **🏗️ Coordinator._build_llm()** — Returns provider config dict or None; cleaner LLM setup path
- **💬 Chat smart context** — Both `p chat` and web `POST /api/chat` now dynamically inject brain data (findings, routes, security, patches, tests, imports) based on detected keywords in user message. Avoids token waste from fixed generic context.
- **🌐 Web UI additions:**
  - `review.html` — undo/redo buttons + JS handlers (calls `/api/undo/{id}` / `/api/redo/{id}`)
  - `settings.html` — watch toggle (`/api/settings/watch`), model set/check (`/api/model/set`), notification add form
  - `api_legacy.py:1643-1668` — `GET /api/notifications` returns HTML fragment for HTMX when `HX-Request` header present

### All 4 files-5 Documents Analyzed vs Current Codebase
- **builder-brief**, **master-plan**, **testing-strategy-v2**, **exploration-mapping-agent** — all read and mapped against current code
- **14 gap/conflict areas** identified; all additive changes, none require tearing down existing code
- **Governor** (pipeline state machine) wraps Coordinator — no dispatch logic rewrite
- **SymbolGraph** alongside ImportGraph — no replacement, parallel data structure
- **SQLite** for symbol graph storage — incremental patch updates instead of full rebuild
- **files-5 deployment shapes** (Docker standalone, embedded SDK, GitHub App) deferred to later phases

---

## File Count Summary

```
patchi/cli/main.py                1
patchi/cli/logo.py                1
patchi/cli/commands/             24   (including 4 new Phase 8 modules)
patchi/core/agents/               3
patchi/core/brain/                7
patchi/core/fix/                  4
patchi/core/hosted/               5
patchi/core/notifications/        5
patchi/core/security/            19   (7 new agent files registered in Phase 9)
patchi/core/testing/              1
patchi/core/ (root)               6   (config, constants, health, memory, queue, snapshot)
patchi/web/                       5
patchi/tests/                    33
patchi/__init__.py                1
─────────────────────────────────────
Total                           103 Python files (__main__.py removed — dead code)
```
