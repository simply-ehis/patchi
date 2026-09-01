# Patchi 0.7.0 — Smart Code Security & Quality Orchestrator

> **⚠️ Pre-1.0.0 Development Preview** — Functional and usable, but still in active development.  
> **Peak stable release is planned for `v1.0.0`** — ~0.4.0 of feature work remains. APIs, agent lists and hosted behavior may still evolve.  
> **Feedback appreciated!** Open an issue, start a discussion, or email **idemudiaehis6@gmail.com**. Your reports directly shape the road to 1.0.

A CLI agent colony + unified web UI that scans, secures, tests and fixes your codebase using static analysis and optional AI.  
**1:1 CLI ↔ Web** — the web is a fancy wrapper; every screen maps to a command. Cross-platform (Windows, Linux, macOS).

> **🚧 This project is in active development.** The current version is a preview — APIs, agents, and hosted behavior may evolve. Feedback and contributions are appreciated!

```bash
pip install .                # local dev
# or
pip install patchi            # from PyPI once published
# with web UI:
pip install ".[web]"
```

**Requires Python 3.11+**

---

## ✨ What's New in 0.7.0

- **Unified Web UI** — one `p web` command serves everything: Dashboard, Brain Map (2D/3D), Findings, Assurance Heatmap, Live Tests, Hosted control plane. See [Web ↔ CLI Parity](docs/web-cli-parity.md).
- **1:1 Project Selection** — `p web` serves the project your terminal is standing in (same walk-up as every `p <command>`). Switch projects live from the header dropdown (`GET /api/tenant/*`).
- **License Noise Trimmed** — `p scan` is now focused by default. Heavy/compliance findings (license for every dep) are hidden unless you opt in: `p scan --with-license` or `p scan --with-extended`.
- **Hosted → Experimental** — live log monitoring works but is flagged as preview (banner in CLI + UI).
- **Smart fixes** — risk-gated `POST /api/fix/apply-all-safe` (only `ALLOW_AUTO` patches), cached `GET /api/security/report` (174s → 0.1s), self-improving checks fixed.

Full list → [PATCHI_V2_UPGRADE_PLAN.md](PATCHI_V2_UPGRADE_PLAN.md) and `AGENT_FEEDBACK.md`.

---

## Quick Start

```bash
cd your-project
p init              # one-time setup
p scan              # full scan (static analysis, no AI tokens)  — license findings hidden by default
p scan --with-license   # include supply-chain license audit when you need it
p scan --deep       # with LLM analysis on changed files
p scan --json       # JSON output for CI/CD
p scan --offline    # static analysis only, no AI calls
p status            # brain health, mode, queue, AI status
p fix               # apply AI-generated fixes (requires scan first)
p fix --dry-run     # preview fixes without applying
p web               # launch unified UI at http://127.0.0.1:1612  (--project <path> to pick a project, --open to launch browser)
p web --project ../other-repo --port 8000
```

---

## CLI Commands

50 registered commands. Major ones:

| Command | Purpose |
|---------|---------|
| `p init` | Initialize Patchi in the current project |
| `p scan` | Scan for issues (`--json`, `--deep`, `--force`, `--offline`, `--with-license`) |
| `p fix` | Apply AI-generated fixes (`--dry-run` to preview) |
| `p test` | Run tests (unit, browser, stress, regression, api, e2e, visual) |
| `p chat` | Interactive AI chat with Patchi (`--stream` for streaming) |
| `p agents` | List/inspect registered agents (`list`, `status`, `reset`) |
| `p deps` | Supply chain security scan |
| `p audit` | Full project audit (scan + security + test + report) |
| `p plan` | Prioritized fix list ranked by importance |
| `p watch` | Auto-scan on file saves |
| `p chains` | Show exploit chains and intent gaps |
| `p findings` | View and manage security findings |
| `p assure` | Assurance campaigns -- prove properties, record evidence |
| `p charter` | Manage project charter and rules |
| `p vr` | Visual regression baseline management |
| `p notify` | Manage notification channels |
| `p hosted` | **(Experimental)** Live monitoring daemon |
| `p web` | Unified web UI -- dashboard, brain map, findings, assurance |
| `p memory` | View or clear scan memory |
| `p patch` | Manage individual patches (`list`, `show`, `apply`, `reject`) |
| `p undo` / `p redo` | Undo/redo applied fixes |
| `p doctor` | System health check -- stale commands, dependencies, config |
| `p cleanup` | Clean stale `.patchi/` artifacts |
| `p report` | Export scan reports |
| `p settings` | View or modify configuration (`show`, `set`, `mode`) |
| `p trend` | Health and quality trend over time |
| `p blame` | Show git blame for a file |
| `p log` | Show git changelog |
| `p update` | Check for and apply updates |
| `p verify` | Independently re-run tests+scan |
| `p auto` | Propose/apply safe fixes for changed files |
| `p impact` | Show change-impact / blast radius |
| `p why` | Explain why a file matters |
| `p restrict` | Manage file restrictions |
| `p key` | Manage API keys |
| `p ai` | AI configuration and status |
| `p model` | Manage local Ollama model |
| `p learn` | Learn project conventions |
| `p agent-stats` | Agent profiling stats and learning state |
| `p goal` | Autonomous mode -- loop until health target |
| `p cross-repo` | Cross-repository dependency intelligence |

Run `p <command> --help` for flags.
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

## Security Agents

54 registered agents in `patchi/core/security/security_agents.py` (lazy-loaded).
Categories:

| Category | Covers |
|----------|--------|
| Injection | SQLi, XSS, command injection, SSRF, CSRF, path traversal |
| Auth | Missing auth, broken access control, JWT, SAML SSO |
| Crypto | Weak hashing, hardcoded keys, SSL/TLS misconfig |
| Secrets | Leaked credentials, API keys, connection strings |
| Supply Chain | CVEs, typosquatting, unpinned deps (**license = opt-in via `--with-license`**) |
| Config/IaC | Debug mode, missing headers, CORS, Docker, K8s, Terraform |
| Compliance | SOC2, HIPAA, PCI-DSS, CIS policy enforcement |
| Privacy | PII handling |
| Runtime | Live app testing, anomaly detection |
| Adversarial | Attack surface analysis, exploit patterns |
| Governance | History, blast radius, drift detection |

Uses Semgrep CE, Gitleaks, OSV-Scanner, and httpx under the hood. Heavy compliance packs (license-for-every-dep) intentionally stay out of the default `p scan` — opt in when you need a full audit.

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
├── web/              ← Unified UI (Mission Control + API) — launch with p web
├── install.sh        ← Linux/macOS installer
├── install.ps1       ← Windows installer
└── tests/            ← 1,300+ tests across ~70 files
```

---

## Key Features

- **Multi-language scanning** — Python, JS, TS, Rust, Go, Java, and more via tree-sitter
- **Git-aware** — incremental scanning via git diff, blame integration
- **Atomic writes + file locking** — crash-safe memory, queue, snapshots
- **Learning brain** — tracks accept/reject patterns, stops suggesting rejected fix types
- **Notifications** — Slack, Discord, email, webhook, Telegram
- **Hosted mode (Experimental)** — live log monitoring, anomaly detection, IP reputation, auto-blocking — *preview, feedback welcome*
- **Governor pipeline** — phase-gated state machine with crash recovery (via `p scan --governor`)
- **Security orchestrator** — deduplication, cross-agent correlation, OWASP Top 10 mapping (CWE-aware, cached report: 174s → 0.1s)
- **Policy engine** — YAML/JSON policy enforcement with compliance packs
- **Verify loop** — security fixes re-checked to confirm resolution

---

## Running Tests

```bash
python -m pytest tests/ -q -x
python -m pytest tests/test_contract.py -q
python tools/deep_audit_web.py   # href/fetch/template/WS/DOM/render/multi-project checks
python tools/e2e_web_v2.py       # live server boot + all pages + APIs + WS
```

---

## License & Pricing

**Patchi Freemium Preview — see [LICENSE](LICENSE).**

- **Free:** Personal use, education, research, open-source, and teams of **fewer than 3 users** (any purpose) — no contact required.
- **Enterprise / teams ≥3:** Please contact **idemudiaehis6@gmail.com** for a license. Trial up to 30 days before contacting is fine.
- **Donations & contributions appreciated** — they directly accelerate the road to **v1.0.0** (peak release).
- Hosted mode is **EXPERIMENTAL** in this preview — not recommended for production use yet.

---

## Feedback

Patchi is in active development. If something is noisy, missing, or broken — please open an issue or email **idemudiaehis6@gmail.com**. Your reports directly shape the road to v1.0.0.

> **Road to 1.0.0:** Peak stable release will lock APIs, ship the full domain taxonomy, and promote hosted out of experimental. Until then, pin `.patchi/` memory formats as best-effort forward-compatible.

## Contributing

Donations and contributions are appreciated and help accelerate development:
- **GitHub Sponsors** — [link in repo](https://github.com/sponsors)
- **Pull requests** — welcome and credited
- **Bug reports** — open an issue or email **idemudiaehis6@gmail.com**

