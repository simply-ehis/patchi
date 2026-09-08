# Patchi v0.7.5

> AI-powered code security & quality orchestrator — CLI agent colony + unified web UI.
> Scans, secures, tests, and fixes your codebase using static analysis and optional AI.
> **1:1 CLI ↔ Web** — every screen maps to a command. Cross-platform (Windows, Linux, macOS).

**Requires Python 3.11+**

---

## What's New in 0.7.5

- **CLI UX module** — spinners, progress bars, colored status, formatted tables, confirmation prompts across all commands
- **Quick readiness check** — `p quick` runs 3 fast agents to validate project health in seconds
- **Interactive fix review** — `p fix-review` presents patches with accept/reject/skip and inline diff view
- **Command families** — `p <family> commands` lists all commands in a family (60 commands, 24 families)
- **Shannon integration** — entropy analysis for advanced obfuscation detection in pentest campaigns
- **Dependency consolidation** — all runtime deps now in main, dev/pentest in extras
- **Security audit fixes** — 7 production bugs fixed (risk gate, queue, memory, applier, health)
- **Version 0.7.5** — bug fixes, dependency updates, CLI UX improvements

Full changelog → [docs/archive/RELEASE-v0.7.5.md](docs/archive/RELEASE-v0.7.5.md)

---

## Quick Start

```bash
# Install
pip install .                # local dev
pip install patchi           # from PyPI (once published)
pip install ".[web]"         # with web UI

# Initialize and scan
cd your-project
p init              # one-time setup
p scan              # full scan (static analysis, no AI tokens)
p scan --with-license   # include supply-chain license audit
p scan --deep       # with LLM analysis on changed files
p scan --json       # JSON output for CI/CD
p scan --offline    # static analysis only, no AI calls

# Check and fix
p quick             # fast readiness check (3 agents)
p status            # brain health, mode, queue, AI status
p fix               # apply AI-generated fixes (requires scan first)
p fix --dry-run     # preview fixes without applying
p fix-review        # interactive review with diff view

# Web UI
p web               # launch at http://127.0.0.1:1612
p web --open        # auto-open browser
```

---

## Commands

**60 commands** across **24 families.** Full reference → [docs/CLI.md](docs/CLI.md)

### Command Families

| Family | Purpose |
|--------|---------|
| `scan` | Scanning & analysis (`scan`, `security`, `deps`, `chains`, `findings`, `blast`, `impact`, `why`) |
| `fix` | Fixing & patching (`fix`, `fix-review`, `auto`, `patch`, `undo`, `redo`, `rollback`) |
| `test` | Testing (`test`, `verify`) |
| `agent` | Agent management (`agents`, `agent-stats`, `quick`, `ready`) |
| `ai` | AI configuration (`ai`, `chat`, `model`, `key`) |
| `config` | Configuration (`settings`, `mode`, `memory`, `cleanup`, `doctor`) |
| `web` | Web UI & reporting (`web`, `report`, `audit`) |
| `charter` | Governance (`charter`, `rules`, `restrict`, `assure`) |
| `notify` | Notifications (`notify`) |
| `hosted` | Live monitoring (`hosted`) — experimental |
| `git` | Git integration (`blame`, `log`, `status`) |
| `dev` | Developer tools (`dev`, `update`, `watch`) |
| `queue` | Task queue (`queue`) |
| `brain` | Knowledge & planning (`brain`, `learn`, `plan`) |
| `vr` | Visual regression (`vr`) |
| `goal` | Autonomous mode (`goal`) |
| `cross-repo` | Cross-repo intelligence (`cross-repo`) |

Run `p <command> --help` for flags. Run `p <family> commands` to list all commands in a family.

---

## Security Agents

**125 registered agents** across 11 categories (lazy-loaded).

| Category | Covers |
|----------|--------|
| Injection | SQLi, XSS, command injection, SSRF, CSRF, path traversal |
| Auth | Missing auth, broken access control, JWT, SAML SSO |
| Crypto | Weak hashing, hardcoded keys, SSL/TLS misconfig |
| Secrets | Leaked credentials, API keys, connection strings |
| Supply Chain | CVEs, typosquatting, unpinned deps (license = opt-in via `--with-license`) |
| Config/IaC | Debug mode, missing headers, CORS, Docker, K8s, Terraform |
| Compliance | SOC2, HIPAA, PCI-DSS, CIS policy enforcement |
| Privacy | PII handling |
| Runtime | Live app testing, anomaly detection |
| Adversarial | Attack surface analysis, exploit patterns |
| Governance | History, blast radius, drift detection |

Uses Semgrep CE, Gitleaks, OSV-Scanner, httpx, Shannon, and CodeQL under the hood.

---

## AI Setup (Optional)

Without AI, Patchi runs structural analysis using static analyzers — free, fast, zero API calls.

**Four AI tiers** (priority order):
1. **Local model via Ollama** — fully offline, zero cost
2. **API keys** — any OpenAI-compatible provider
3. **Free keys** — Groq, Google AI, OpenRouter, Mistral, Together AI
4. **AI Horde fallback** — anonymous community key, zero setup

**14 built-in providers:** OpenAI, Anthropic, Google, Groq, Mistral, Cohere, Together AI, Fireworks, Perplexity, OpenRouter, DeepSeek, xAI, NVIDIA, Hugging Face, plus any custom OpenAI-compatible endpoint.

Keys stored in `.patchi/keys.json`, never sent elsewhere.

---

## Modes

| Mode | Behaviour |
|------|-----------|
| `confirm` (default) | Every fix requires approval |
| `auto` | Low-risk fixes auto-apply, risky ones ask |
| `autopilot` | Full trust — applies everything |

---

## Architecture

```
patchi/
├── cli/                    # Command-line interface
│   ├── main.py             # Root parser, lazy imports
│   ├── framework.py        # Command registration + family routing
│   ├── registry.py         # 60 registered commands
│   ├── ux.py               # Spinners, progress bars, formatting
│   ├── console.py          # Rich console output
│   └── commands/           # One file per command (60 files)
│
├── core/
│   ├── brain/              # AST scanning, import graph, language detection
│   │   ├── brain.py        # Brain class — main orchestrator
│   │   ├── scanner.py      # File discovery and scanning
│   │   ├── languages.py    # Language support (20+ via tree-sitter)
│   │   ├── layered_brain.py # Layered architecture analysis
│   │   ├── charter.py      # Project guard rails
│   │   ├── brain_context.py # Injectable context bridge
│   │   └── ast_utils/      # AST manipulation utilities
│   │
│   ├── agents/             # Agent framework
│   │   ├── base.py         # BaseAgent, Finding, Severity, register()
│   │   ├── coordinator.py  # Multi-agent orchestration
│   │   ├── governor.py     # Phase-gated state machine
│   │   └── cache.py        # Tree-sitter parse cache
│   │
│   ├── security/           # 125 security agents
│   │   ├── orchestrator.py # Cross-agent correlation
│   │   ├── security_agents.py # Agent registry
│   │   ├── pentest/        # Pentest toolkit (shannon, metasploit, nuclei, sqlmap, dalfox, ffuf)
│   │   └── ...             # 100+ specialized agents
│   │
│   ├── ai/                 # AI integration
│   │   ├── client.py       # Unified AI client (14 providers)
│   │   ├── model_router.py # Cost-aware model routing
│   │   └── agent_profiler.py # Agent performance tracking
│   │
│   ├── fix/                # Fix application
│   │   ├── base.py         # Fix generation with AI
│   │   ├── risk_gate.py    # Risk assessment for fixes
│   │   └── patch.py        # Patch management
│   │
│   ├── testing/            # Test execution
│   │   ├── live_v2/        # Playwright browser testing
│   │   │   ├── runner.py   # Browser test runner
│   │   │   └── video_recorder.py # Video evidence capture
│   │   └── ...             # Unit, stress, visual regression
│   │
│   ├── config.py           # Project configuration
│   ├── constants.py        # Shared constants
│   ├── memory.py           # Atomic persistent memory
│   ├── queue.py            # File-locked task queue
│   ├── snapshot.py         # Atomic rollback
│   └── health.py           # Health scoring (0-100)
│
├── web/                    # Unified web UI
│   ├── app.py              # FastAPI application
│   ├── routes/             # Page routes (Jinja2 templates)
│   ├── api/                # REST API endpoints
│   ├── templates/          # Jinja2 HTML templates
│   └── static/             # CSS, JS, brain map assets
│
└── tests/                  # 1,000+ tests across ~70 files
```

---

## Key Features

- **Multi-language scanning** — Python, JS, TS, Rust, Go, Java, C, C++, Swift, Ruby, PHP, C#, Kotlin, Dart, SQL, HTML, CSS, Svelte, Bash, and more via tree-sitter
- **Git-aware** — incremental scanning via git diff, blame integration
- **Atomic writes + file locking** — crash-safe memory, queue, snapshots
- **Learning brain** — tracks accept/reject patterns, stops suggesting rejected fix types
- **Notifications** — Slack, Discord, email, webhook, Telegram
- **Hosted mode (Experimental)** — live log monitoring, anomaly detection, IP reputation, auto-blocking
- **Governor pipeline** — phase-gated state machine with crash recovery (via `p scan --governor`)
- **Security orchestrator** — deduplication, cross-agent correlation, OWASP Top 10 mapping
- **Policy engine** — YAML/JSON policy enforcement with compliance packs
- **Verify loop** — security fixes re-checked to confirm resolution
- **CLI UX** — spinners, progress bars, formatted tables, confirmation prompts

---

## Running Tests

```bash
python -m pytest tests/ -q -x           # full suite
python -m pytest tests/test_contract.py -q  # contract tests
python tools/deep_audit_web.py           # web UI audit
python tools/e2e_web_v2.py              # end-to-end
```

---

## License & Pricing

**Patchi Freemium Preview — see [LICENSE](LICENSE).**

- **Free:** Personal use, education, research, open-source, and teams of **fewer than 3 users** — no contact required.
- **Enterprise / teams ≥ 3:** Contact **idemudiaehis6@gmail.com** for a license. Trial up to 30 days before contacting is fine.
- **Donations & contributions appreciated** — they directly accelerate the road to **v1.0.0**.
- Hosted mode is **EXPERIMENTAL** — not recommended for production use yet.

---

## Contributing

Donations and contributions are appreciated:
- **GitHub Sponsors** — [link in repo](https://github.com/sponsors)
- **Pull requests** — welcome and credited
- **Bug reports** — open an issue or email **idemudiaehis6@gmail.com**

---

## Roadmap

**v1.0.0** will lock APIs, ship the full domain taxonomy, and promote hosted out of experimental.
Until then, pin `.patchi/` memory formats as best-effort forward-compatible.
