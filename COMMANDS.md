# Patchi CLI — Command Reference

> **Agent Knowledge Doc** — Every command, flag, and variant. Read this before using the CLI.

**Prefix:** `p` (or `python -m patchi`)
**Shell:** PowerShell 7+ / bash
**Requires:** Python 3.11+

---

## Global Flags

These work with any command:

| Flag | Effect |
|------|--------|
| `--json` | Output as JSON (machine-readable) |
| `--deep` | Enable LLM-assisted analysis (costs tokens) |
| `--force` | Skip confirmations |
| `--offline` | Static analysis only, no AI calls |
| `--verbose` / `-v` | Extra debug output |
| `--quiet` / `-q` | Minimal output |
| `--no-logo` | Skip ASCII art logo (for CI) |

---

## 1. Scanning & Analysis

### `p scan [area]`
Full codebase scan. Runs all security agents, brain analysis, and import graph.

| Flag | What it does |
|------|-------------|
| `--deep` | LLM analysis on changed files (costs tokens) |
| `--offline` | Static analysis only |
| `--force` | Re-scan even if nothing changed |
| `--dry-run` | Show what would be scanned |
| `--json` | JSON output |
| `--file <path>` | Scan a single file |
| `--changed` | Only scan git-diff changed files |
| `--since <ref>` | Scan changes since git ref (commit, branch, tag) |
| `--fail-on <sev>` | Exit non-zero if finding ≥ severity (critical/high/medium) |
| `--with-license` | Include supply-chain license audit |
| `--with-extended` | Include extended compliance findings |
| `--with-attackers` | Run attacker simulations |
| `--with-campaigns` | Run campaign scenarios |
| `--with-fuzz` | Include fuzzing |
| `--red-team` | Full red team assessment |
| `--dast` | Dynamic application security testing (Playwright) |
| `--pipeline` | Governor pipeline mode (phase-gated) |
| `--daemon` | Background scan mode |
| `--no-side` | Skip side-effect agents |

**Examples:**
```bash
p scan                    # standard scan
p scan --deep             # with AI analysis
p scan --changed          # only changed files
p scan --offline --json   # static only, JSON output
p scan --red-team         # full red team
p scan api/ --deep        # scan specific directory
```

### `p heatmap`
Visual assurance heatmap of security domain coverage.

| Flag | Effect |
|------|--------|
| `--json` | JSON output |

### `p rules`
List and validate security rules/domains.

| Flag | Effect |
|------|--------|
| `--validate` | Validate all rule YAML files |
| `--which <id>` | Show details for a specific rule |

### `p blame <file> [line]`
Git blame integration. Shows who last changed a file/line and associated risks.

### `p log`
Git changelog for the project.

| Flag | Effect |
|------|--------|
| `--since <ref>` | Changes since ref (default: HEAD~10) |

---

## 2. Fixing & Patching

### `p fix [area]`
Apply AI-generated fixes for findings.

| Flag | What it does |
|------|-------------|
| `--dry-run` | Preview fixes without applying |
| `--preview` | Same as --dry-run |
| `--safe-all` | Auto-apply all safe fixes (skip risky ones) |

**Modes** (set via `p settings mode`):
- `confirm` (default): every fix requires approval
- `auto`: low-risk auto-apply, risky ones ask
- `autopilot`: applies everything

### `p review`
Review pending patches with unified diffs. Shows what will change, let's you approve/reject per-patch.

### `p auto <files..>`
Smart auto-fix for specific files. Analyzes changed files and proposes safe fixes.

| Flag | Effect |
|------|--------|
| `--apply` | Apply fixes (default is preview) |
| `--unsafe` | Include risky fixes |
| `--reject` | Reject all proposed fixes |

### `p undo [patch_id]`
Undo an applied fix. No argument = undo last.

### `p redo [patch_id]`
Redo a previously undone fix.

### `p rollback <patch_id>`
Full rollback to pre-patch state.

### `p patch`
Patch management.

| Subcommand | What it does |
|------------|-------------|
| `p patch list` | List all patches (`--json` for JSON) |
| `p patch show <id>` | Show patch details and diff |
| `p patch apply <id>` | Apply a specific patch |
| `p patch reject <id>` | Reject a patch |
| `p patch undo [id]` | Undo a patch |
| `p patch redo [id]` | Redo a patch |
| `p patch rollback <id>` | Full rollback |

---

## 3. Testing

### `p test [type] [area]`
Run test suites.

| Type | What it runs |
|------|-------------|
| `unit` | Unit tests |
| `smoke` | Quick smoke tests |
| `browser` | Browser-based tests (Playwright) |
| `e2e` | End-to-end flow tests |
| `visual` | Visual regression tests |
| `full` | All test types |
| `attack` | Security attack tests |
| `generate` | AI-generate test files |
| `report` | Show test history |
| `config` | Show/set test config |

| Flag | Effect |
|------|--------|
| `--last N` | Show last N test runs (for `report`) |
| `--attack` | Include attack tests |

**Examples:**
```bash
p test                    # run unit tests
p test browser            # browser tests
p test generate unit      # AI-generate unit tests
p test report --last 5    # show last 5 runs
p test config show        # show test configuration
```

### `p verify`
Independently re-run tests + scan to verify fixes.

| Flag | Effect |
|------|--------|
| `--no-scan` | Skip scan, tests only |
| `--claim` | Claim verification results |

### `p vr`
Visual regression management.

| Action | What it does |
|--------|-------------|
| `p vr capture` | Capture current screenshots |
| `p vr baseline` | Set current as baseline |
| `p vr compare` | Compare current vs baseline |
| `p vr diff` | Show differences |
| `p vr reset` | Reset baseline |
| `p vr list` | List available baselines |

---

## 4. AI & Models

### `p ai`
AI configuration and status.

| Subcommand | What it does |
|------------|-------------|
| `p ai status` | Show AI provider status |
| `p ai test` | Test AI connection |
| `p ai add` | Add a new AI provider |
| `p ai remove <name>` | Remove a provider |
| `p ai profiles` | List provider profiles |

### `p chat [message]`
Interactive AI chat with Patchi. Has full brain context (project purpose, tech stack, risks).

| Flag | Effect |
|------|--------|
| `--stream` | Stream responses in real-time |
| `--explain-all` | Explain all findings |

### `p key`
API key management.

| Subcommand | What it does |
|------------|-------------|
| `p key add` | Add API key (interactive provider selection) |
| `p key list` | List stored keys |
| `p key remove <nick>` | Remove a key |
| `p key test [nick]` | Test a key connection |

**Supported providers:** OpenAI, Anthropic, Google, Groq, Mistral, Cohere, Together AI, Fireworks, Perplexity, OpenRouter, DeepSeek, xAI, NVIDIA, Hugging Face, Custom (any OpenAI-compatible)

### `p model`
Local Ollama model management.

| Subcommand | What it does |
|------------|-------------|
| `p model status` | Show current model |
| `p model set <name>` | Set active model |
| `p model list` | List available models |

---

## 5. Agents & Memory

### `p agents`
Agent registry inspection.

| Subcommand | What it does |
|------------|-------------|
| `p agents list [group]` | List agents (optionally filter by group) |
| `p agents status` | Show agent execution status |
| `p agents reset [name]` | Reset agent state |

### `p agent-stats [name]`
Agent profiling and learning stats.

| Flag | Effect |
|------|--------|
| `--profile` | Show detailed profile |
| `--learning` | Show learning state |
| `--json` | JSON output |

### `p memory`
Scan memory management.

| Subcommand | What it does |
|------------|-------------|
| `p memory show <category>` | Show memory for a category |
| `p memory delete <cat\|all>` | Delete memory |

**Categories:** brain, patches, issues, failed, scans, restrictions, tokens

### `p learn`
Learn project conventions from codebase patterns.

| Flag | Effect |
|------|--------|
| `--force` | Force re-learn |

---

## 6. Restrictions & Config

### `p restrict`
File restriction management. Prevents Patchi from touching certain files.

| Subcommand | What it does |
|------------|-------------|
| `p restrict add <path>` | Block Patchi from modifying a file |
| `p restrict scan-only <path>` | Scan but never modify |
| `p restrict sensitive <path>` | Mark as sensitive (extra caution) |
| `p restrict list` | List restrictions |
| `p restrict remove <path>` | Remove restriction |
| `p restrict disable <path>` | Temporarily disable |
| `p restrict enable <path>` | Re-enable |

| Flag | Effect |
|------|--------|
| `--reason` | Why this restriction |

### `p settings`
Configuration management.

| Subcommand | What it does |
|------------|-------------|
| `p settings show` | Show all settings |
| `p settings set <key> <value>` | Set a config value |

### `p settings mode [mode]`
Set fix mode.

| Mode | Behavior |
|------|----------|
| `confirm` | Every fix requires approval (default) |
| `auto` | Low-risk auto-apply, risky ask |
| `autopilot` | Full trust, applies everything |

### `p init`
Initialize Patchi in a project. Creates `.patchi/` directory with config, memory, and charter.

| Flag | Effect |
|------|--------|
| `--no-logo` | Skip logo animation |

---

## 7. Audit, Assurance & Reporting

### `p audit`
Full project audit: scan + security + test + report in one command.

| Flag | Effect |
|------|--------|
| `--quick` | Quick audit (skip heavy agents) |
| `--json` | JSON output |
| `--plan` | Generate fix plan |
| `--plan-file <path>` | Save plan to file |
| `--intent` | Include intent analysis |
| `--no-scan` | Skip scan, use cached results |
| `--html` | HTML report output |

### `p assure`
Assurance campaigns — prove security properties, record evidence.

| Flag | Effect |
|------|--------|
| `--json` | JSON output |
| `--reset` | Reset assurance state |
| `--run-attackers` | Run attacker simulations |
| `--run-campaigns` | Run assurance campaigns |
| `--run-all` | Run all assurance checks |
| `--chain-report` | Generate chain analysis report |

### `p report [export|weekly]`
Export scan reports.

| Flag | Effect |
|------|--------|
| `--format <fmt>` | Output format: `markdown` or `json` |

### `p chains`
Show exploit chains and intent gaps.

| Flag | Effect |
|------|--------|
| `--min-score <n>` | Minimum chain score |
| `--min-severity <sev>` | Minimum severity |
| `--json` | JSON output |
| `--fix` | Show fix suggestions |
| `--analyze` | Deep chain analysis |

### `p findings`
View and manage security findings.

| Flag | Effect |
|------|--------|
| `--summary` | Summary view |
| `--save-baseline` | Save current as baseline |
| `--json` | JSON output |

### `p plan [area]`
Prioritized fix list ranked by importance.

| Flag | Effect |
|------|--------|
| `--format <fmt>` | Output format |
| `--missing-import` | Show missing imports |
| `--json` | JSON output |
| `--html` | HTML output |

### `p trend [metric]`
Health and quality trend over time.

| Metric | What it shows |
|--------|-------------|
| `security` | Security score trend |
| `tests` | Test coverage trend |

| Flag | Effect |
|------|--------|
| `--last N` | Last N data points |
| `--json` | JSON output |

---

## 8. Web & Hosted

### `p web`
Launch unified web UI (Mission Control).

| Flag | Effect |
|------|--------|
| `--host <addr>` | Bind address (default: 127.0.0.1) |
| `--port <n>` | Port (default: 1612) |
| `--open` | Open browser automatically |
| `--project <path>` | Serve a different project |

**Pages:** Dashboard, Brain Map (2D/3D), Findings, Review, Guard, Chat, Brain, Council, Attack Timeline, Live Tests, Hosted, Settings, History, Charter, Assurance, Tokens, Self-Improvement, Smart Agent

### `p hosted` **(EXPERIMENTAL)**
Live monitoring daemon. Tails log files, detects anomalies, blocks IPs.

| Subcommand | What it does |
|------------|-------------|
| `p hosted init` | Configure (log path, format, escalation) |
| `p hosted worker` | Tail log file, parse lines |
| `p hosted daemon` | Background daemon with health checks |
| `p hosted daemon --guard` | Daemon + anomaly detection |
| `p hosted stop` | Kill daemon |
| `p hosted guard` | Live guard: anomaly detection + IP reputation |
| `p hosted status` | Show threats and audit summary (`--json`) |
| `p hosted logs` | Stream audit log |
| `p hosted token add` | Generate admin token |
| `p hosted token list` | List tokens |
| `p hosted token revoke <id>` | Revoke token |
| `p hosted block <ip>` | Block IP |
| `p hosted unblock <ip>` | Unblock IP |
| `p hosted disconnect` | Clear hosted config |

**Supported log formats:** nginx, apache, caddy, uvicorn, gunicorn, cloudflare, json

---

## 9. Notifications

### `p notify`
Notification channel management.

| Subcommand | What it does |
|------------|-------------|
| `p notify list` | List channels + quiet hours |
| `p notify add <type>` | Add channel (email/slack/discord/webhook/telegram) |
| `p notify remove <name>` | Remove channel |
| `p notify test [name]` | Send test alert |
| `p notify ack <id>` | Acknowledge alert |
| `p notify flush` | Flush digest queue |
| `p notify pending` | Show unacknowledged escalations |

---

## 10. Developer Tools & Diagnostics

### `p doctor`
System health check — stale commands, dependencies, config.

| Flag | Effect |
|------|--------|
| `--verbose` | Detailed output |
| `--json` | JSON output |
| `--fix` | Auto-fix detected issues |

### `p check`
Quick health check.

| Flag | Effect |
|------|--------|
| `--fix` | Auto-fix issues |
| `--json` | JSON output |

### `p dev`
Developer utilities.

| Action | What it does |
|--------|-------------|
| `p dev check` | Environment check |
| `p dev test` | Quick test run |
| `p dev security` | Quick security check |
| `p dev playwright` | Check Playwright installation |
| `p dev docs` | Generate docs |
| `p dev hook` | Manage git hooks |

| Flag | Effect |
|------|--------|
| `--verbose` | Extra detail |
| `--json` | JSON output |
| `--strict` | Strict mode |
| `--auto-fix` | Auto-fix issues |
| `--fast` | Fast mode (skip heavy checks) |

### `p watch [area]`
Auto-scan on file saves.

| Flag | Effect |
|------|--------|
| `--dry-run` | Preview without acting |
| `--preview` | Same as --dry-run |
| `--auto-fix` | Auto-apply safe fixes |

### `p status`
Brain health, mode, queue, AI status.

| Flag | Effect |
|------|--------|
| `--json` | JSON output |
| `--deep` | Detailed status |
| `--validate` | Validate config |
| `--verbose` | Extra detail |

### `p cockpit`
Real-time monitoring dashboard (CLI).

| Flag | Effect |
|------|--------|
| `--area <n>` | Monitoring area |
| `--interval <s>` | Refresh interval (default: 15s) |
| `--poll <s>` | Poll rate (default: 1s) |
| `--once` | Single snapshot |
| `--scan-secrets` | Include secrets scan |

### `p goal`
Autonomous mode — loop until health target reached.

| Flag | Effect |
|------|--------|
| `--max-loops <n>` | Max iterations (default: 5) |
| `--target <score>` | Target health score (default: 100) |
| `--dry-run` | Preview without acting |

---

## 11. System & Maintenance

### `p update`
Check for and apply updates.

| Flag | Effect |
|------|--------|
| `--check` | Check only, don't update |
| `--force` | Force update |
| `--auto` | Auto-update |

### `p deps`
Supply chain security scan.

| Flag | Effect |
|------|--------|
| `--sbom` | Generate SBOM |
| `--licenses` | License audit |
| `--outdated` | Show outdated deps |
| `--cve` | CVE check |
| `--json` | JSON output |

### `p cleanup`
Clean stale `.patchi/` artifacts.

| Flag | Effect |
|------|--------|
| `--apply` | Actually clean (default is preview) |
| `--all` | Clean everything |
| `--older-than <dur>` | Age filter (e.g., `7d`, `24h`, `30m`) |
| `--json` | JSON output |

### `p why <path>`
Explain why a file matters (dependency analysis, risk score, findings).

### `p impact [files..]` (alias: `p blast`)
Show change impact / blast radius.

| Flag | Effect |
|------|--------|
| `--all` | Show all impacts |
| `--json` | JSON output |

### `p governance`
GUARD infrastructure surface — the audit trail, policy, history, blast radius,
event triage, and CI config generation behind one command.

| Subcommand | What it does |
|------------|-------------|
| `p governance actions` | Show the governance action log (what agents/fixes/gates did) |
| `p governance policy [target]` | Show the policy; with a target, test it against the policy |
| `p governance history` | Scan history + findings lifecycle analytics |
| `p governance verify <id>` | Mark a finding's fix as verified (`--force` to override status) |
| `p governance impact <symbol>` | Blast radius: count references across the codebase |
| `p governance triage` | Event-anomaly stats; `--start` subscribes to the live EventBus |
| `p governance generate` | Preview CI configs; `--write` creates them, never overwrites without `--force` |

| Flag | Effect |
|------|--------|
| `--json` | JSON output (all subcommands) |

### `p charter`
Project charter and rules management.

| Subcommand | What it does |
|------------|-------------|
| `p charter show` | Show current charter |
| `p charter set <text>` | Set charter from natural language |
| `p charter set --ai` | Generate charter with AI |
| `p charter check` | Check violations against codebase |
| `p charter check --rebuild` | Rebuild and check |
| `p charter hooks` | Show git hooks |
| `p charter hooks --install` | Install git hooks |

### `p link`
Frontend-backend linking for monorepos.

| Action | What it does |
|--------|-------------|
| `p link status` | Show link status |
| `p link add` | Add link |
| `p link confirm` | Confirm link |
| `p link remove` | Remove link |
| `p link list` | List links |

| Flag | Effect |
|------|--------|
| `--frontend <path>` | Frontend directory |
| `--backend <path>` | Backend directory |
| `--frontend-url <url>` | Frontend URL |
| `--backend-url <url>` | Backend URL |

### `p cross-repo [projects..]`
Cross-repository dependency intelligence.

| Subcommand | What it does |
|------------|-------------|
| `p cross-repo scan` | Scan cross-repo deps |
| `p cross-repo health` | Health check across repos |
| `p cross-repo fix` | Fix cross-repo issues |

| Flag | Effect |
|------|--------|
| `--all` | Scan all known repos |
| `--mode <mode>` | Scan mode |
| `--target <repo>` | Target specific repo |

### `p plugins [args..]`
Plugin management.

| Subcommand | What it does |
|------------|-------------|
| `p plugins list` | List plugins |
| `p plugins run <name>` | Run a plugin |
| `p plugins run-all` | Run all plugins |
| `p plugins info <name>` | Plugin info |

### `p command` / `p help [group]`
List all commands or show help for a group.

| Flag | Effect |
|------|--------|
| `--all` | Show all commands |
| `--json` | JSON output |
| `--write-md` | Generate markdown reference |

---

## 12. CI/CD Integration

The web server exposes CI/CD-friendly endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/cicd/health` | Health check (unauthenticated) |
| `POST /api/cicd/scan` | Sync scan (blocks until done) |
| `POST /api/cicd/scan/async` | Async scan (returns immediately) |
| `GET /api/cicd/scan/status` | Current scan status |
| `GET /api/cicd/scan/results` | Latest results |
| `GET /api/cicd/findings` | Findings with filters |
| `GET /api/cicd/summary` | Project summary |

**Auth:** `X-API-Key` header (auto-generated at `.patchi/api_key` or env `PATCHI_API_KEY`)

---

## Quick Reference — Most Used Commands

```bash
# First time
p init                          # initialize in project
p scan                          # first scan
p web --open                    # open dashboard

# Daily workflow
p scan --changed                # scan what you changed
p fix --dry-run                 # preview fixes
p fix                           # apply fixes
p test                          # run tests
p audit --quick                 # quick health check

# Security deep dive
p scan --deep --red-team        # full security assessment
p chains                        # exploit chain analysis
p assure --run-all              # assurance campaigns
p deps --cve                    # dependency vulnerabilities

# CI/CD
p scan --json --fail-on high    # fail pipeline on high+ findings
p audit --json                  # full audit as JSON
```

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `PATCHI_CORS_ORIGINS` | Comma-separated allowed origins for web UI |
| `PATCHI_API_KEY` | CI/CD API key |
| `PATCHI_KEY_<NAME>` | Provider API keys |

---

## Config Files

| File | Purpose |
|------|---------|
| `.patchi/config.yaml` | Project configuration |
| `.patchi/keys.json` | API keys (never sent elsewhere) |
| `.patchi/charter.yaml` | Project rules and conventions |
| `.patchi/memory/` | Scan memory, learning state |
| `.patchi/patches/` | Applied patches history |
| `.patchi/restrictions.json` | File restrictions |
