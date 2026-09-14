# Patchi Use Case Guide

## First-Time Setup

```bash
# Install (cross-platform)
pip install .

# Or use the installer scripts
./install.sh          # Linux/macOS
.\install.ps1         # Windows

# Initialize in your project
cd your-project
p init                # scaffolds .patchi/, sets up alias, configures AI

# Verify everything works
p doctor              # check dependencies and config
p status              # brain health, mode, queue, AI status
```

By default, Patchi runs in **confirm mode** — it proposes fixes but asks before applying.
Run `p mode auto` for fully autonomous mode.

---

## Daily Workflow

### Morning sync

```bash
cd your-project
p scan                # fresh brain scan — catches new issues
p status              # health score, findings count
p fix                 # apply fixes for known issues
```

### While coding

```bash
p scan --deep --file src/auth.py   # deep analysis on one file
p scan --no-side                   # fast source-only scan
p scan --pipeline                  # full scan + auto-defense (ConfidenceGate + DefenseLayer)
p security                         # run all 40 security agents
p security injection               # run specific agent
p security --json                  # structured JSON output
p fix --security                   # security fixes with verify loop
p explain                          # learn what each finding means
p test                             # run test suite
p test security                    # generate security-focused tests
```

### Before commit

```bash
p scan                # full scan
p scan --contract     # review and confirm app contract flows
p review              # review pending fixes
p explain             # understand all findings
p report              # export markdown report for PR description
```

---

## Learning About Findings

```bash
p explain                          # explain all findings with what/why/how
p explain --type hardcoded_secret  # explain a specific category
p explain <finding_id>             # explain a specific finding
```

Each explanation includes:
- **What** the issue is
- **Why** it matters (security risk, maintenance burden, etc.)
- **How** to fix it (code examples in your language)
- **CWE reference** where applicable

---

### Weekly report

```bash
p report weekly            # generate and save health report
p report weekly --email    # generate, save, and email if configured
```

The weekly report includes project summary, health score breakdown, findings by severity, recent patches, and top recommendations.

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/patchi.yml
name: Patchi
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Patchi
        run: pip install git+https://github.com/your-org/patchi.git
      - name: Init and scan
        run: |
          p init
          p scan --json > patchi-report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: patchi-report
          path: patchi-report.json
```

---

## Team Collaboration

### Shared configuration

Commit `.patchi/config.json` to share settings (keys stay local in `.patchi/keys.json`):
- Scan mode and depth preferences
- Notification channels
- Device tier and queue mode

### Notification channels

```bash
p notify add slack --webhook-url https://hooks.slack.com/...
p notify add discord --webhook-url https://discord.com/api/webhooks/...
p notify test
```

---

## Scanning Strategies

| Goal | Command |
|------|---------|
| Full scan (all scanners) | `p scan` |
| Fast source-only scan | `p scan --no-side` |
| Deep scan with AI | `p scan --deep` |
| Scan one file | `p scan --file src/app.py` |
| Scan specific area | `p scan src/auth` |
| Force re-scan | `p scan --force` |
| Review app contract | `p scan --contract` |
| JSON output for CI | `p scan --json` |
| Offline (no AI calls) | `p scan --offline` |

### Contract Flow Inference

Patchi infers your app's critical flows (login, checkout, admin, etc.) from routes and file structure:

- **High confidence:** Route + matching source file with app-relevant purpose — shown for confirmation
- **Medium confidence:** Route match only (no qualifying file) — shown for confirmation
- **Low confidence:** File match only (no route evidence) — **hidden by default**, run `p scan --contract --all-flows` to review

Flows from test files, scanners, config files, and documentation are excluded from inference entirely.

### Project Understanding

Patchi automatically learns what your project does:

1. **AI-powered:** When AI is configured, the brain generates a one-sentence project purpose from your code structure
2. **Fallback heuristic:** Without AI, it aggregates file purposes and framework detection
3. **Displayed in:** `p brain --show` (first section)

### Doc Validation

Patchi can verify README and documentation claims against actual code:

```bash
# (Integrated into p scan — planned for interactive mode)
# Standalone:
python -c "from patchi.core.brain.doc_validator import validate_project_docs; ..."
```

Validated claims are stored in brain memory; stale claims (docs say it exists but code doesn't have it) are flagged.

---

### Circuit Breaker

If an agent fails 3 consecutive times, it is automatically skipped in future runs. Use `p agents reset <name>` to re-enable it, or `p agents reset` to reset all.

---

## Hosted Mode

Monitor live applications with auto-restart and health checks:

```bash
p hosted init         # set up log path and format
p hosted daemon       # start with auto-restart + health checks
p hosted guard        # live anomaly detection + watchlist
p hosted status       # top threats and audit log
p hosted stop         # stop running daemon
```

Features:
- Statistical + ML anomaly detection
- IP reputation database with auto-blocking
- Watchlist tracking with time-decay scoring
- 7 log format parsers
- PID management and graceful shutdown

---

## Web UI

```bash
p web                 # open at localhost:4321
p web --port 8080     # custom port
p web --host 0.0.0.0  # expose on network
```

14 panels: Overview, Brain Map (force-directed), Queue, Review, History, Security, Tests, Guard, Memory, Notifications, Agents, Diagnostics, Chat, Settings.

---

## Fix Management

```bash
p fix                 # generate fixes for all findings
p fix --dry-run       # preview without applying
p review              # review pending patches
p undo                # undo last applied fix
p redo                # redo last undone fix
p patch list          # list all patches
p patch show <id>     # show patch details
p patch apply <id>    # apply a specific patch
p patch reject <id>   # reject a patch
p agents list         # list all agents with last-run status
p agents reset [name] # reset circuit breaker for an agent
```

### Fix Verify Loop

When `p fix --security` runs, each fix is verified by re-running the original scanner agent on the patched file. If the finding persists, the patch is retried (up to `verify_retries` times, default 2). Failed patches are reported with the remaining finding details.

### AttackAgent (Metasploit Integration)

Run Metasploit auxiliary/scanner probes against your local project:

```bash
p test --attack
```

Requires msfrpcd running and pymetasploit3 installed:
```bash
pip install patchi[msf]
msfrpcd -P your_password -S -a 127.0.0.1
```

- Targets localhost (127.0.0.1) only — never external hosts
- Auto-picks modules based on detected framework (Flask, Django, FastAPI, Express, React, Spring)
- Configurable port via brain data or routes (default 8000)
- Configurable msfrpcd port via `msf_port` (default 55553)
- Falls back gracefully if pymetasploit3 is not installed
