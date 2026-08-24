# Patchi 0.6.0

A CLI agent colony that scans, secures, and fixes your codebase using static analysis
and optional AI. Cross-platform (Windows, Linux, macOS).

```bash
pip install .
# or: pip install -e ".[dev]"
```

**Requires Python 3.11+**

---

## Quick Start

```bash
cd your-project
p init              # one-time setup
p scan              # full scan (static analysis, no AI tokens)
p scan --deep       # with LLM analysis on changed files
p scan --json       # JSON output for CI/CD
p scan --offline    # static analysis only, no AI calls
p status            # brain health, mode, queue, AI status
p fix               # apply AI-generated fixes (requires scan first)
p fix --dry-run     # preview fixes without applying
p explain           # what/why/how for each finding
```

---

## CLI Commands

43 commands in `patchi/cli/commands/`. Major ones:

| Command | Purpose |
|---------|---------|
| `p scan` | Scan for issues (supports `--json`, `--deep`, `--force`, `--offline`) |
| `p fix` | Apply AI-generated fixes |
| `p security` | Run security agents (`--json`, or filter by type) |
| `p test` | Run tests (unit, browser, stress, regression, api, e2e, etc.) |
| `p audit` | Full project audit (scan + security + test + report) |
| `p plan` | Prioritized fix list ranked by importance |
| `p explain` | Plain-English explanation of findings |
| `p chat` | Chat with Patchi about your project |
| `p watch` | Auto-scan on file saves |
| `p notify` | Manage notification channels |
| `p hosted` | Live monitoring daemon |
| `p web` | Archived — shows notice with CLI alternatives |
| `p brain` | View project purpose, domain, contract flows |
| `p memory` | View or clear scan memory |
| `p patch` | Manage individual patches |
| `p undo` / `p redo` | Undo/redo applied fixes |
| `p doctor` | Validate setup and config |
| `p report` | Export scan reports |
| `p mode` | View/change scan mode (confirm/auto/autopilot) |
| `p agents` | List registered agents |
| `p blast` | Blast radius analysis |
| `p trend` | Quality trend over time |

---

## AI Setup (Optional)

Without AI, Patchi runs structural analysis using static analyzers — free, fast, zero API calls.

**Four AI tiers** (priority order):
1. **Local model via Ollama** — fully offline, zero cost
2. **API keys** — any OpenAI-compatible provider
3. **Free keys** — Groq, Google AI, OpenRouter, Mistral, Together AI
4. **AI Horde fallback** — anonymous community key, zero setup

**14 built-in providers:** OpenAI, Anthropic, Google, Groq, Mistral, Cohere, Together AI,
Fireworks, Perplexity, OpenRouter, DeepSeek, xAI, NVIDIA, Hugging Face, plus any
custom OpenAI-compatible endpoint.

Keys stored in `.patchi/keys.json`, never sent elsewhere.

---

## Security Agents

54 registered agents in `patchi/core/security/security_agents.py` (lazy-loaded).
Categories:

| Category | Covers |
|----------|--------|
| Injection | SQLi, XSS, command injection, SSRF, CSRF, path traversal |
| Auth | Missing auth, broken access control, JWT, SAML SSO |
| Crypto | Weak hashing, hardcoded keys, SSL/TLS misconfig |
| Secrets | Leaked credentials, API keys, connection strings |
| Supply Chain | CVEs, typosquatting, unpinned deps |
| Config/IaC | Debug mode, missing headers, CORS, Docker, K8s, Terraform |
| Compliance | SOC2, HIPAA, PCI-DSS, CIS policy enforcement |
| Privacy | PII handling |
| Runtime | Live app testing, anomaly detection |
| Adversarial | Attack surface analysis, exploit patterns |
| Governance | History, blast radius, drift detection |

Uses Semgrep CE, Gitleaks, OSV-Scanner, and httpx under the hood.

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
├── cli/              ← 43 command modules
│   ├── main.py       ← Root parser
│   └── commands/     ← One file per command
├── core/
│   ├── agents/       ← Scanner agents + governor
│   ├── brain/        ← AST scanning, import graph, language detection
│   ├── ai/           ← Unified AI client, 14 providers
│   ├── fix/          ← Fix agents, risk gate, patch applier
│   ├── testing/      ← Test agents (unit, browser, stress, etc.)
│   ├── security/     ← 54 security agents, orchestrator, policies
│   ├── hosted/       ← Anomaly detection, IP reputation, log parsers
│   ├── notifications/← Channels, digest, escalation
│   ├── export/       ← Report export (SARIF, JSON, text)
│   ├── config.py
│   ├── constants.py
│   ├── memory.py     ← Atomic writes, persistent scan memory
│   ├── queue.py      ← File-locked task queue
│   ├── snapshot.py   ← Atomic rollback
│   └── health.py     ← Health score (0–100, A–F)
├── web/              ← Archived (see .patchi/web_archive/)
├── install.sh        ← Linux/macOS installer
├── install.ps1       ← Windows installer
└── tests/            ← 1,200+ tests across 66 files
```

---

## Key Features

- **Multi-language scanning** — Python, JS, TS, Rust, Go, Java, and more via tree-sitter
- **Git-aware** — incremental scanning via git diff, blame integration
- **Atomic writes + file locking** — crash-safe memory, queue, snapshots
- **Learning brain** — tracks accept/reject patterns, stops suggesting rejected fix types
- **Notifications** — Slack, Discord, email, webhook, Telegram
- **Hosted mode** — live log monitoring, anomaly detection, IP reputation, auto-blocking
- **Governor pipeline** — phase-gated state machine with crash recovery (via `p scan --governor`)
- **Security orchestrator** — deduplication, cross-agent correlation, OWASP Top 10 mapping
- **Policy engine** — YAML/JSON policy enforcement with compliance packs
- **Verify loop** — security fixes re-checked to confirm resolution

---

## Running Tests

```bash
python -m pytest tests/ -q -x
python -m pytest tests/test_contract.py -q
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
