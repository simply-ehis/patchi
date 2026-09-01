# Patchi Usage Guide

A practical guide to using Patchi for code security and quality analysis.

---

## Installation

```bash
# From source (local dev)
git clone <repo-url>
cd Patchi_COMPLETE
pip install -e .

# With web UI support
pip install -e ".[web]"
```

**Requires Python 3.11+**

---

## Quick Start

```bash
# 1. Initialize in your project
cd your-project
p init

# 2. Run a scan
p scan

# 3. View results
p findings

# 4. Launch the web dashboard
p web
```

---

## Core Workflows

### Scanning Your Project

```bash
p scan                    # Full scan (static analysis, no AI tokens)
p scan --deep             # With LLM analysis on changed files
p scan --offline          # Static analysis only, no AI calls
p scan --json             # JSON output for CI/CD
p scan --changed          # Only scan git-changed files
p scan --with-license     # Include supply-chain license audit
```

### Fixing Issues

```bash
p fix                     # Apply AI-generated fixes (requires scan first)
p fix --dry-run           # Preview fixes without applying
p auto                    # Propose/apply safe fixes for changed files
```

### Testing

```bash
p test                    # Run all tests
p test --unit             # Unit tests only
p test --browser          # Browser tests (Playwright)
p test --stress           # Stress/load tests
p test --visual           # Visual regression tests
```

### Security Analysis

```bash
p security                # Run all security agents
p chains                  # Show exploit chains
p findings                # View all findings
p deps                    # Supply chain scan
```

### AI Chat

```bash
p chat                    # Interactive AI chat
p chat "explain XSS"      # Ask about a specific topic
p chat --stream           # Streaming responses
```

### Monitoring

```bash
p watch                   # Auto-scan on file saves
p hosted                  # (Experimental) Live monitoring daemon
p trend                   # Quality trend over time
```

---

## Web Dashboard

Launch the unified web UI:

```bash
p web                     # Default port 1612
p web --port 8000         # Custom port
p web --project ../other  # Scan a different project
p web --open              # Auto-open browser
```

### Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Main overview with brain map, findings, scan controls |
| Findings | `/findings` | All security findings with filtering and export |
| Assurance | `/assurance` | Coverage heatmap and claim verification |
| Live Tests | `/live-tests` | Browser test recordings and visual regression |
| Self-Improvement | `/self-improvement` | Agent profiles and learning state |
| Doctor | `/doctor` | System health and stale command detection |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` or `Ctrl+F` | Focus brain map search |
| `↑↓` | Navigate search results |
| `Enter` | Select search match |
| `Escape` | Clear search |
| `Ctrl+Shift+X` | Cancel all running operations |

---

## Configuration

### Modes

| Mode | Behavior |
|------|----------|
| `confirm` (default) | Every fix requires approval |
| `auto` | Low-risk fixes auto-apply, risky ones ask |
| `autopilot` | Full trust — applies everything |

```bash
p mode                    # View current mode
p settings mode auto      # Switch to auto mode
```

### API Keys

```bash
p ai add                  # Add an API key interactively
p ai status               # Show configured keys
p ai test                 # Test a key connection
```

### Charter (Guard Rails)

```bash
p charter set rules.yaml  # Set project charter from file
p charter check           # Check code against charter
p charter hooks           # Manage git hooks
```

---

## CI/CD Integration

### GitHub Actions

The included `.github/workflows/ci.yml` runs:
- **test** — ruff + mypy + pytest (Python 3.11, 3.12 matrix)
- **dev-check** — Full `p dev check` gate
- **security-scan** — Security agents on fixtures
- **audit** — Full audit gate

### Pre-commit Hook

```bash
p dev hook                # Install pre-commit hook
p dev hook --strict       # Install with strict mode (blocks on errors)
```

### JSON Output

```bash
p scan --json             # JSON scan results for pipeline consumption
p findings --json         # JSON findings export
p cleanup --json          # JSON cleanup report
```

---

## Useful Commands

```bash
p status                  # Brain health, mode, queue, AI status
p doctor                  # System health check
p cleanup                 # Clean stale .patchi/ artifacts
p memory show <category>  # View scan memory
p report                  # Generate analysis report
p blame <file>            # Git blame for a file
p log                     # Git changelog
p update                  # Check for updates
p vr baseline             # Capture visual regression baselines
p vr list                 # List baselines
```

---

## Getting Help

```bash
p <command> --help        # Help for any command
p --help                  # List all commands
p command                 # List all commands with tags
```

---

## License

Patchi is free for personal use and teams of fewer than 3 users.
Enterprise teams (3+) should contact **idemudiaehis6@gmail.com**.

See [LICENSE](LICENSE) for full terms.
