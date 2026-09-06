# Patchi — Real-World Testing Plan

**Version:** 0.7.2
**Date:** June 28 2026
**Scope:** All security phases (0-11), web UI, hosted mode, CLI

---

## 1. Smoke Tests (automated, run on every commit)

| # | Test | What it checks | Pass criteria |
|---|---|---|---|
| 1.1 | `python -m pytest tests/ -x` | All 800+ unit tests pass | 0 failures |
| 1.2 | `p init` in empty dir | Creates .patchi/ directory | dir exists with config.json |
| 1.3 | `p status` after init | Shows health score | No crash, outputs table |
| 1.4 | `p scan` on small Python project | Brain builds, agents run | Health score computed, no exceptions |
| 1.5 | `p security` on small project | All 25 security agents run | Findings returned, no agent crashes |
| 1.6 | `p fix --security` | SecurityFixer generates patches | Patches proposed (may be 0 if clean) |
| 1.7 | `p web` starts | FastAPI server starts | HTTP 200 on /api/health |

## 2. Security Agent Tests (automated)

### 2.1 Deterministic Scanner Tests
| # | Agent | Test fixture | Expected finding |
|---|---|---|---|
| 2.1.1 | InjectionAgent | Python file with `cursor.execute("SELECT * FROM users WHERE id=" + user_id)` | SQL Injection (CRITICAL) |
| 2.1.2 | InjectionAgent | Python file with `os.system("ping " + host)` | Command Injection (CRITICAL) |
| 2.1.3 | InjectionAgent | JS file with `document.write(userInput)` | XSS (HIGH) |
| 2.1.4 | AuthZAgent | Flask route with `@app.route('/admin')` and no `@login_required` | Missing Auth (HIGH) |
| 2.1.5 | CryptoAgent | Python with `hashlib.md5(data)` | Weak Hash (HIGH) |
| 2.1.6 | CryptoAgent | Python with `key = "ABCDEFGHIJKLMNOP1234"` | Hardcoded Key (HIGH) |
| 2.1.7 | NetworkAgent | Config with `SSLv3` | Weak SSL (CRITICAL) |
| 2.1.8 | NetworkAgent | Source with `http://example.com` and no HTTPS enforcement | Plain HTTP (MEDIUM) |
| 2.1.9 | PrivacyAgent | Source with `email`, `ssn`, `credit_card` patterns | PII findings |
| 2.1.10 | ComplianceAgent | Source with `PCI DSS` reference | Compliance finding (INFO) |
| 2.1.11 | MisconfigAgent | Python with `DEBUG = True` | Debug enabled (HIGH) |
| 2.1.12 | JWTSecurityAgent | Python with `jwt.decode(token, verify=False)` | JWT without verification |
| 2.1.13 | SensitiveDataAgent | Source with `AKIAIOSFODNN7EXAMPLE` | AWS key (CRITICAL) |
| 2.1.14 | DependencyVulnerabilityAgent | package.json with known vulnerable dep | CVE found |
| 2.1.15 | SecretsGuard | .env file with `API_KEY=secret123` | Hardcoded secret |
| 2.1.16 | SupplyChainAgent | package.json with `numpi` dependency | Typosquatting (HIGH) |
| 2.1.17 | IaCScannerAgent | Dockerfile with `USER root` | Container runs as root |
| 2.1.18 | IaCScannerAgent | docker-compose with `privileged: true` | Privileged container |
| 2.1.19 | IaCScannerAgent | Terraform with `acl = "public"` | Public S3 bucket |
| 2.1.20 | PolicyEngineAgent | Code with `password = "admin"` | Policy violation |
| 2.1.21 | CVEMonitorAgent | requirements.txt with known vuln | CVE found |
| 2.1.22 | RedTeamAgent | Python with `eval(user_input)` | eval() usage (CRITICAL) |
| 2.1.23 | RedTeamAgent | Python with `DEBUG = True` | Debug mode (HIGH) |

### 2.2 Orchestrator Tests
| # | Test | Expected |
|---|---|---|
| 2.2.1 | Two agents find same issue at same line | Deduplicated to 1 finding, confirmed_by has both |
| 2.2.2 | Different findings remain separate | Total findings == input count |
| 2.2.3 | CWE-89 maps to OWASP A03 | owasp_category == "A03:2021 Injection" |
| 2.2.4 | Composite score higher for CRITICAL | CRITICAL finding score > HIGH finding score |

### 2.3 Verify Loop Tests
| # | Test | Expected |
|---|---|---|
| 2.3.1 | Fix removes hardcoded secret | verify_fix returns True |
| 2.3.2 | Fix doesn't remove secret | verify_fix returns False, confidence lowered |
| 2.3.3 | Fix changes target line | verify_fix returns True |

## 3. CLI Integration Tests (automated)

| # | Command | Test |
|---|---|---|
| 3.1 | `p security --json` | Output is valid JSON with findings array |
| 3.2 | `p security injection` | Only InjectionAgent runs |
| 3.3 | `p security --all` | All 25 agents run (check agent count in output) |
| 3.4 | `p test security` | SecurityTestAgent generates pytest files in tests/security/ |
| 3.5 | `p fix --security` | Patches proposed, risk gate consulted |
| 3.6 | `p report` | Markdown report includes security section |
| 3.7 | `p report --format json` | JSON export includes all finding data |
| 3.8 | `p restrict add secret.py no_touch` | File excluded from scanning |
| 3.9 | `p mode auto` | Mode changes, auto-apply enabled |
| 3.10 | `p agents list` | Lists all 35+ agents (scanner + fix + test + security) |

## 4. Web UI Tests (automated via httpx TestClient)

| # | Endpoint | Test |
|---|---|---|
| 4.1 | `GET /api/health` | Returns 200 |
| 4.2 | `GET /api/config` | Returns 200 with config dict |
| 4.3 | `GET /api/findings` | Returns 200 with findings dict |
| 4.4 | `GET /api/health-breakdown` | Returns 200 with total, components |
| 4.5 | `POST /api/scan/start` | Starts scan, returns 200 |
| 4.6 | `GET /api/report/markdown` | Returns markdown string |
| 4.7 | `POST /api/key/set` | Stores API key, returns 200 |
| 4.8 | `GET /api/status` | Returns brain + health data |

## 5. Hosted Mode Tests (automated)

| # | Test | Expected |
|---|---|---|
| 5.1 | `p hosted init` | Creates .patchi/hosted/ directory |
| 5.2 | Token generation | Token stored as HMAC hash, not plaintext |
| 5.3 | Token validation | Valid token passes, invalid rejected |
| 5.4 | Audit log | Events logged to rotating JSON-lines file |
| 5.5 | Anomaly detection | Statistical detector identifies outliers |
| 5.6 | Watchlist | IP scoring with time decay works |

## 6. Edge Case Tests

| # | Scenario | Expected |
|---|---|---|
| 6.1 | Empty project (no files) | All agents return gracefully, no crash |
| 6.2 | Binary file in scan | Skipped without crash |
| 6.3 | File with encoding errors | Handled via errors="ignore" |
| 6.4 | Circular imports | Detected by import graph, reported |
| 6.5 | 1000+ files project | Completes in <60s, no OOM |
| 6.6 | No AI key configured | Agents run without AI, static analysis only |
| 6.7 | Restricted path (no_touch) | Agent skips the path |
| 6.8 | Concurrent scans | No race conditions on .patchi/ files |

## 7. Regression Tests

| # | What | How |
|---|---|---|
| 7.1 | Health score stability | Same project produces same score across runs |
| 7.2 | Finding consistency | Same code produces same findings (deterministic agents) |
| 7.3 | Fix safety | Applied fixes don't break existing tests |
| 7.4 | Snapshot rollback | Undo restores original file content exactly |
| 7.5 | Memory persistence | Scan results survive across CLI invocations |

## 8. Performance Tests

| # | Metric | Target |
|---|---|---|
| 8.1 | `p scan` on 100-file project | <10s |
| 8.2 | `p security` on 100-file project | <30s (without network calls) |
| 8.3 | `p fix --security` on 10 findings | <60s |
| 8.4 | Memory usage on 1000-file project | <500MB |
| 8.5 | Web API response time | <200ms for all endpoints |

## 9. Manual Tests (human verification)

| # | Test | Steps |
|---|---|---|
| 9.1 | First-run experience | Fresh `p init` → `p scan` → `p status` — is the output clear and helpful? |
| 9.2 | Fix review flow | `p fix --security` → review proposed patches → apply/reject — is the UX intuitive? |
| 9.3 | Web dashboard | Open browser → navigate panels → is the Brain Map readable? |
| 9.4 | Notification flow | Configure Slack webhook → trigger alert → verify message arrives |
| 9.5 | Hosted mode setup | `p hosted init` → generate token → connect from another terminal |
| 9.6 | Logo animation | `p init` — does the ASCII logo animate correctly on terminal? |
| 9.7 | Error messages | Run `p security` outside project dir — is the error message clear? |

## 10. Security-Specific Validation

| # | Test | Expected |
|---|---|---|
| 10.1 | Patchi doesn't leak API keys | Keys stored in .patchi/.env, never in logs or JSON output |
| 10.2 | Snapshot doesn't store secrets | Snapshots are file content only, no env vars |
| 10.3 | Risk gate blocks high-risk in CONFIRM mode | No auto-apply when mode=confirm |
| 10.4 | Restriction enforcement | no_touch files are never read or modified |
| 10.5 | AI response parsing | Malformed AI responses don't crash the fix pipeline |

---

## Test Execution Order

1. **Unit tests** (`pytest tests/`) — must all pass before anything else
2. **Agent registration** — verify all 35+ agents are registered and importable
3. **Security agent tests** — deterministic, no network, fast
4. **CLI integration** — run real commands against test fixtures
5. **Web API** — TestClient against FastAPI endpoints
6. **Edge cases** — empty projects, binary files, encoding errors
7. **Performance** — timing assertions on key operations
8. **Manual** — human verification of UX flows
