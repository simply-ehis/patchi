# Patchi Developer Commands

Quick reference for every command and flag in Patchi.

> Web UI commands are now active — use `p web` to launch the HTMX dashboard.

---

## Core Workflow

| Command | What it does |
|---------|-------------|
| `p init` | Set up Patchi in your project (creates `.patchi/` config) |
| `p init --no-logo` | Initialize without logo draw (for CI) |
| `p scan` | Full brain scan — discovers files, routes, imports, dead code |
| `p scan src/auth` | Scan only a specific folder or path |
| `p scan --deep` | Deep scan with AI analysis of changed files |
| `p scan --file app.py` | Analyze one specific file in depth |
| `p scan --offline` | Static-only scan, zero AI token cost |
| `p scan --force` | Re-scan even if the brain cache is fresh |
| `p scan --dry-run` | Preview what would be scanned without parsing |
| `p scan --governor` | Full scan with Governor v2 pipeline (state machine, crash recovery, phased analysis) |
| `p scan --contract` | Review and confirm app contract flows |
| `p scan --all-flows` | Show all flows including low-confidence (used with --contract) |
| `p scan --no-side` | Skip config/env/CI files, scan source only |
| `p scan --json` | Output results as JSON for piping to other tools |
| `p scan --pipeline` | Full scan + security pipeline (ConfidenceGate + DefenseLayer) |
| `p scan --daemon` | Start background scan scheduler daemon |
| `p security` | Run all 54 security scan types |
| `p security report` | Full report with orchestrator dedup and OWASP mapping |
| `p status` | Health score, mode, queue state, key status |
| `p fix` | AI generates fixes for high-severity findings |
| `p fix --dry-run` | Preview fixes without applying them |
| `p review` | Review pending patches with diffs |
| `p patch list` | List all patches in the queue |
| `p patch show <id>` | Show details of one patch |
| `p patch apply <id>` | Apply a specific patch |
| `p patch reject <id>` | Reject a specific patch |
| `p undo` | Undo the last applied fix |
| `p undo <id>` | Undo a specific patch by ID |
| `p redo` | Redo the last undone fix |
| `p rollback <id>` | Roll back to before a specific patch |

---

## Security Scanning

| Command | What it does |
|---------|-------------|
| `p security` | Run all 54 security scan types |
| `p security <type>` | Run a single security scan type |
| `p security <type> <area>` | Scope scan to a specific area/path |
| `p security report` | Full report with orchestrator dedup and OWASP mapping |
| `p security --help` | Show all scan types |
| `p security --policy <file>` | Run policy engine with a specific policy file (e.g. `--policy soc2.yaml`) |
| `p scan --pipeline` | Full scan + defense pipeline (ConfidenceGate + DefenseLayer) |

### Individual Security Agents

Run any single agent by name:

| Command | What it does |
|---------|-------------|
| `p security taint` | Data flow tracking from sources to sinks |
| `p security secrets` | Gitleaks secret scan (API keys, passwords, tokens) |
| `p security config` | Semgrep SAST scan for code patterns |
| `p security headers` | HTTP security header audit (needs running server) |
| `p security ratelimit` | Check if auth routes have rate limiting |
| `p security cors` | CORS configuration audit |
| `p security deps` | Dependency CVE check via OSV API |
| `p security probe` | Offensive probing (requires dev_mode=true) |
| `p security jwt` | JWT implementation analysis (weak algo, missing expiry) |
| `p security sensitive` | PII and credential exposure scan |
| `p security auth` | Authentication and session security audit |
| `p security ssrf` | SSRF vulnerability detection |
| `p security injection` | SQLi, XSS, command injection, path traversal |
| `p security authz` | Broken access control, IDOR, privilege escalation |
| `p security crypto` | Weak hashing, hardcoded keys, weak encryption |
| `p security network` | SSL/TLS config, weak ciphers, HTTPS enforcement |
| `p security privacy` | PII handling, GDPR/CCPA compliance |
| `p security depvuln` | Multi-ecosystem dependency CVE check |
| `p security compliance` | PCI DSS, HIPAA, GDPR, SOX pattern detection |
| `p security secrets_guard` | Pre-apply secrets gate, .env/Docker/K8s scanning |
| `p security supply` | Supply chain: typosquatting, pinning, license check |
| `p security iac` | IaC: Dockerfile, docker-compose, K8s, Terraform |
| `p security container` | Container image CVE scanning (needs Trivy) |
| `p security policy` | YAML/JSON policy enforcement (SOC2, HIPAA, PCI-DSS) |
| `p security cve` | OSV API CVE monitoring for npm/PyPI |
| `p security redteam` | Attack surface analysis, vulnerable patterns |
| `p security precheck` | Layer 0: instant banned-API + lint checks |
| `p security runtime` | Runtime header, TLS, method tampering (needs app_url) |
| `p security appmap` | Crawl live app, map pages/forms/entry points |
| `p security browsertest` | Playwright XSS/SQLi/auth bypass testing |
| `p security evidence` | Screenshot/video evidence capture |
| `p security blast` | Blast radius analysis for proposed fixes |
| `p security governance` | Action logging + policy gate |
| `p security history` | Scan history + analytics |

---

## Testing

| Command | What it does |
|---------|-------------|
| `p test` | Run default tests (unit + regression) |
| `p test unit` | Unit tests only |
| `p test regression` | Regression tests only |
| `p test browser` | Browser tests via Playwright |
| `p test stress` | Stress tests via Locust (k6 skeleton available for manual use) |
| `p test accessibility` | Accessibility audit (axe-core) |
| `p test api` | API contract validation |
| `p test buttons` | Button/link/input click tests |
| `p test layout` | Responsive layout tests (4 viewports) |
| `p test e2e` | End-to-end flow tests |
| `p test visual` | Visual regression (screenshot comparison) |
| `p test smoke` | Quick smoke test (buttons + layout + a11y) |
| `p test full` | Run all test agents |
| `p test generate` | AI generates a full test suite |
| `p test generate unit` | AI generates unit tests only |
| `p test generate e2e` | AI generates E2E tests only |
| `p test report` | View test run history |
| `p test report --last 10` | Show last 10 test runs |
| `p test config show` | Show current test configuration |
| `p test config set key value` | Update a config value |
| `p test config flows` | View/manage contract flows configuration |
| `p test security` | Generate route-specific security tests via SecurityTestAgent |
| `p test --attack` | Run Metasploit auxiliary/scanner probes against localhost (needs msfrpcd + pymetasploit3) |

---

## Brain & Knowledge

| Command | What it does |
|---------|-------------|
| `p brain` | Generate `.patchi/BRAIN.md` — plain English project summary |
| `p brain --show` | Print BRAIN.md to terminal |
| `p brain --force` | Force regenerate even if no new scan |
| `p learn` | Detect project conventions and patterns |
| `p learn --force` | Re-learn even if patterns already stored |
| `p learn patterns` | Show recorded fix patterns |
| `p explain` | Explain a finding in plain English |
| `p explain --type <category>` | Explain a category of findings |
| `p blast <file>` | Show what breaks if you change a file |
| `p blast --all` | Blast radius for all files |
| `p trend` | Health and quality trend over time |
| `p trend security` | Security finding trends specifically |
| `p trend tests` | Test coverage trends specifically |
| `p trend --last <N>` | Show last N entries (default: 20) |

---

## Hosted Mode (Production Monitoring)

| Command | What it does |
|---------|-------------|
| `p hosted init` | Set up hosted mode (log path, worker config) |
| `p hosted worker` | Start background log-watching worker |
| `p hosted guard` | Start live guard with anomaly detection |
| `p hosted daemon` | Start worker with auto-restart + health checks |
| `p hosted daemon --guard` | Daemon with anomaly detection included |
| `p hosted stop` | Stop a running daemon |
| `p hosted status` | Show watchlist top threats and audit log |
| `p hosted status --json` | Output status as JSON |
| `p hosted logs` | Stream audit log in real time |
| `p hosted token add` | Generate new admin token (shown once) |
| `p hosted token list` | List all active tokens |
| `p hosted token revoke <id>` | Revoke a token by ID |
| `p hosted block <ip>` | Block an IP address |
| `p hosted unblock <ip>` | Unblock an IP address |
| `p hosted disconnect` | Clear hosted mode config |

---

## Configuration & Management

| Command | What it does |
|---------|-------------|
| `p mode` | Show current operating mode |
| `p mode confirm` | Every fix requires your approval |
| `p mode auto` | Low-risk fixes auto-apply, high-risk asks |
| `p mode autopilot` | All fixes apply automatically |
| `p queue` | Show task queue |
| `p queue pause` | Pause the queue |
| `p queue resume` | Resume the queue |
| `p queue skip` | Skip next item |
| `p queue clear` | Clear the queue |
| `p queue mode single` | Process one item at a time |
| `p queue mode multi` | Process multiple items in parallel |
| `p queue mode off` | Turn off queue processing |
| `p restrict add <path>` | Block Patchi from touching a file |
| `p restrict add <path> --reason "..."` | Add restriction with an optional reason |
| `p restrict scan-only <path>` | Mark path as scan-only (can scan but not modify) |
| `p restrict sensitive <path>` | Mark path as sensitive (extra caution) |
| `p restrict list` | Show all restrictions |
| `p restrict remove <path>` | Remove a restriction |
| `p restrict disable <path>` | Temporarily disable a restriction |
| `p restrict enable <path>` | Re-enable a restriction |
| `p key add` | Add an API key (interactive) |
| `p key list` | List configured keys with status |
| `p key remove <name>` | Remove a key by nickname |
| `p key test` | Test all configured keys |
| `p key test <name>` | Test a specific key connection |
| `p model set <model>` | Set Ollama model |
| `p model list` | List available local models |
| `p model status` | Show model connection health |
| `p settings show` | Show all settings |
| `p settings set key value` | Update a setting |
| `p access add <name> --env VAR` | Add dev access token from environment variable |
| `p access list` | List configured tokens (names only) |
| `p access remove <name>` | Remove a dev access token |

---

## Notifications

| Command | What it does |
|---------|-------------|
| `p notify list` | List notification channels |
| `p notify add email` | Add email notifications |
| `p notify add slack` | Add Slack notifications |
| `p notify add discord` | Add Discord notifications |
| `p notify add webhook` | Add webhook notifications |
| `p notify add telegram` | Add Telegram notifications |
| `p notify remove <name>` | Remove a notification channel |
| `p notify test` | Send test alert to all channels |
| `p notify test <name>` | Send test alert to a specific channel |
| `p notify ack <id>` | Acknowledge a CRITICAL/HIGH alert |
| `p notify flush` | Force-flush the digest queue now |
| `p notify pending` | Show unacknowledged escalation alerts |

---

## Reports & Output

| Command | What it does |
|---------|-------------|
| `p report` | Generate analysis report |
| `p report export` | Export report |
| `p report export --format markdown` | Export as markdown (default) |
| `p report export --format json` | Export as JSON |
| `p report export --format sarif` | Export as SARIF |
| `p report weekly` | Generate and save weekly health report |
| `p audit` | Full audit: scan + security + test + health, with Plan-vs-Built drift |
| `p audit --quick` | Quick audit (skip tests) |
| `p audit --json` | Output as JSON |
| `p audit --plan` | Snapshot current real scope (files/symbols/hashes) as the agreed Plan (no scans) |
| `p audit --intent "..."` | Describe the plan intent when saving (`--plan`) |
| `p audit --plan-file <file>` | Audit the built state against a specific plan/spec file |
| `p audit --no-scan` | Re-audit using stored scan results (skip re-scan) |
| `p audit --html <file>` | Write a self-contained HTML report (Playwright-viewable) |
| `p plan` | Prioritized Fix List — what to fix first across the project (ranked) |
| `p plan <area>` | Limit the fix list to one area/path |
| `p plan --format` | Also include formatter (format) fixes |
| `p plan --missing-import` | Also include cross-module missing-import suggestions (noisy) |
| `p plan --json` | Output the fix list as JSON |
| `p plan --html <file>` | Write the fix list as a self-contained HTML report (Playwright-viewable) |

---

## AI & Chat

| Command | What it does |
|---------|-------------|
| `p chat` | Interactive AI chat about your project |
| `p chat "what does this do?"` | Ask a question directly |
| `p ai status` | Show AI provider status |
| `p ai test` | Test AI connection |
| `p ai` | AI status and test connection |
| `p ai add` | Add a new API key |
| `p ai remove <name>` | Remove an API key by name |

---

## Web UI

| Command | What it does |
|---------|-------------|
| `p web` | Start the Web UI (HTMX dashboard, default port 1612) |
| `p web --port 8080` | Start on a specific port |
| `p web --host 0.0.0.0` | Listen on all interfaces (default: 127.0.0.1) |
| `p web --no-browser` | Don't open browser automatically |
| `p web --cert <path>` | Path to SSL certificate (enables HTTPS) |
| `p web --key <path>` | Path to SSL private key file |

### Web UI Pages

| Page | Endpoint | Description |
|------|----------|-------------|
| **Dashboard** | `/` | Brain Map + security overview |
| **Findings** | `/findings` | Scan findings with filters |
| **Review** | `/review` | Patch review with diffs |
| **Guard** | `/guard` | Hosted guard monitoring (live events, threats, IP block/unblock) |
| **Tokens** | `/tokens` | Admin API token management (generate/revoke) |
| **Chat** | `/chat` | Security AI chat |
| **Brain** | `/brain` | Brain knowledge viewer |
| **History** | `/history` | Scan and action history |
| **Settings** | `/settings` | Configuration panel |

### Hosted API Endpoints (under `/api/hosted`)

| Endpoint | Description |
|----------|-------------|
| `GET /api/hosted/status` | Hosted mode status |
| `POST /api/hosted/init` | Initialize hosted mode |
| `GET /api/hosted/tokens` | List admin tokens |
| `POST /api/hosted/tokens` | Generate admin token |
| `DELETE /api/hosted/tokens/{id}` | Revoke admin token |
| `POST /api/hosted/block/{ip}` | Block an IP |
| `POST /api/hosted/unblock/{ip}` | Unblock an IP |
| `GET /api/guard/threats` | HTMX fragment: top threats table |
| `GET /api/guard/live` | HTMX fragment: live event stream |

## Utilities & Developer Tools

| Command | What it does |
|---------|-------------|
| `p help` | Show main help |
| `p help <group>` | Show help for a specific command group |
| `p dev` | Developer console — project info, testing docs, security status, CLI reference |
| `p dev info` | Show project health, config, security status |
| `p dev test` | Show all testing tools and how to use them |
| `p dev playwright` | Playwright/browser testing documentation |
| `p dev security` | Security pipeline status and architecture |
| `p dev docs` | Full CLI commands reference |
| `p doctor` | Validate setup, check dependencies |
| `p watch` | Auto-scan on file saves |
| `p memory show brain` | Show brain knowledge data |
| `p memory show patches` | Show patch history |
| `p memory show issues` | Show known issues |
| `p memory delete all` | Clear all memory |
| `p memory delete <category>` | Clear memory for a specific category |
| `p agents list [group]` | List agents with last-run status |
| `p agents status` | Detailed agent run history |
| `p agents reset [name]` | Reset circuit breaker for one or all agents |

### Git & Supply Chain

| Command | What it does |
|---------|-------------|
| `p blame <file>` | Show git blame for a file with line-level annotations |
| `p blame <file> <line>` | Blame a specific line number |
| `p log` | Show git changelog (last 10 commits by default) |
| `p log --since HEAD~20` | Show last 20 commits |
| `p deps` | Supply chain security scan (SBOM, licenses, outdated, CVEs) |
| `p deps --sbom` | Generate Software Bill of Materials |
| `p deps --licenses` | Check license compliance |
| `p deps --outdated` | Check for outdated packages |
| `p deps --cve` | Check for known CVEs |
| `p learn` | Detect project conventions and patterns |
| `p learn --force` | Re-learn even if patterns already stored |
| `p learn patterns` | Show recorded fix patterns |

---

## Running Individual Agents

Every agent can be run standalone through the security or test commands:

```bash
# Run a single security agent
p security taint
p security secrets
p security injection

# Run a single test agent
p test unit
p test browser
p test accessibility

# Run all agents of a type
p security          # all 54 security scan types
p test              # default test agents
p test full         # all 12 test agents
```

---

## Global Flags

These work with any command (including `p scan` where `--dry-run` has a more specific description):

| Flag | What it does |
|------|-------------|
| `--version` | Show Patchi version |
| `--json` | Output as JSON |
| `--quiet` | Errors only |
| `--verbose` | Show full details |
| `--dry-run` | Preview actions without executing |
| `--no-logo` | Skip logo (for CI) |
