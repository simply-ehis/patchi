# Patchi — Technical Overview

## What Patchi Does

Patchi is an intelligent code quality agent that scans, fixes, secures, and monitors software projects. It works on any Python, JavaScript, TypeScript, PHP, or mixed-language codebase.

**The core loop:**
1. **Scan** — Parse every file using AST (tree-sitter), build import graph, detect framework, map routes, find dead code, detect secrets
2. **Analyze** — 125 security agents run in parallel, each specializing in one area (injection, auth, crypto, secrets, supply chain, config, compliance, privacy, runtime, adversarial, governance)
3. **Fix** — Fix agents generate surgical patches using AI, scored by risk and confidence
4. **Review** — User reviews patches before applying (or autopilot mode applies automatically)
5. **Guard** — Hosted mode monitors live applications with anomaly detection and auto-blocking

## Key Components

### The Brain (`core/brain/`)

The Brain is the orchestrator. Before any agent runs, the Brain:
- Discovers all source files (respecting `.gitignore` and ignore patterns)
- Parses each file with tree-sitter AST (Python, JS, TS, PHP, Rust, Go, Java, and more)
- Builds a complete import dependency graph
- Detects the web framework (Django, Flask, FastAPI, Express, Next.js, etc.)
- Maps all routes and their handlers
- Infers the app contract (critical flows that must never break)
- Saves everything to `.patchi/memory/brain.json`

### BrainContext Bridge (`core/brain/brain_context.py`)

All brain systems connected into a single injectable object:
- Enriched context, project reader, body tags
- Domain loader (800 security domains, 2,955 playbooks)
- Reasoning engine for context-aware analysis

### Security Agents (`core/security/`)

125 registered agents across 11 categories:

| Category | Agents | Covers |
|----------|--------|--------|
| Injection | 15+ | SQLi, XSS, command injection, SSRF, CSRF, path traversal |
| Auth | 10+ | Missing auth, broken access control, JWT, SAML SSO |
| Crypto | 8+ | Weak hashing, hardcoded keys, SSL/TLS misconfig |
| Secrets | 8+ | Leaked credentials, API keys, connection strings |
| Supply Chain | 12+ | CVEs, typosquatting, unpinned deps |
| Config/IaC | 10+ | Debug mode, missing headers, CORS, Docker, K8s, Terraform |
| Compliance | 8+ | SOC2, HIPAA, PCI-DSS, CIS policy enforcement |
| Privacy | 5+ | PII handling |
| Runtime | 8+ | Live app testing, anomaly detection |
| Adversarial | 10+ | Attack surface analysis, exploit patterns |
| Governance | 8+ | History, blast radius, drift detection |

All agents are lazy-loaded — only run when needed. Circuit breakers prevent runaway agents.

### Scanner Agents (`core/agents/`)

11 specialized scanner agents run in parallel:

| Agent | What It Finds |
|-------|---------------|
| CoreScanner | File structure, functions, classes, imports |
| DeadCodeScanner | Unreachable files, broken imports, uncertain code |
| DuplicateScanner | AST-normalized code duplication |
| EnvScanner | Hardcoded secrets, env var references |
| DependencyScanner | Vulnerable/outdated packages (CVE lookup) |
| RouteGraphScanner | Framework routes, unprotected endpoints |
| TypeScanner | TypeScript `any`, unsafe casts, `@ts-ignore` |
| CommentScanner | TODO/FIXME/HACK tracking |
| UIScanner | React/Vue components, missing prop types |
| TestScanner | Test coverage gaps |
| SideFileScanner | Config files, CI/CD, build scripts |

All scanners filter `node_modules`, `.venv`, `__pycache__`, `dist`, `build` automatically.

### Fix Agents (`core/fix/`)

AI-powered fix agents generate patches:

| Agent | Skill |
|-------|-------|
| CodeFixer | Bug fixes, null checks, error handling |
| SecurityFixer | SQL injection, XSS, path traversal, SSRF |
| DeadCodeRemover | Safe deletion of confirmed dead code |
| DependencyFixer | Version bumps for vulnerable deps |
| EnvFixer | Move secrets to environment variables |
| TypeFixer | TypeScript type improvements |
| RefactorAgent | Extract duplicated logic |
| UnitTestRunner | Generate test skeletons |

Each agent has a detailed system prompt with domain-specific instructions. Patches are risk-scored (0-100) and confidence-scored before presentation.

### Risk Gate (`core/fix/risk_gate.py`)

Every patch passes through the risk gate:
- **Low risk (0-30):** Auto-applied in `auto` mode
- **Medium risk (31-60):** Requires review in `confirm` mode
- **High risk (61-100):** Always requires review, blocks if contract not locked

Risk factors: blast radius (how many files import this), auth/payment paths, file count, agent confidence.

### Health Score (`core/health.py`)

0-100 score with A-F grade:
- Security posture (35%): findings severity, secrets, vulnerable deps
- Test coverage (25%): source files with test counterparts
- Dead code ratio (20%): confirmed dead files
- Dependency health (10%): packages with known CVEs
- App contract (10%): confirmed critical flows

### AI Layer (`core/ai/`)

Unified AI client supporting 14 providers:
- **Ollama** (local, offline, free)
- **OpenAI-compatible** (OpenAI, Groq, DeepSeek, xAI, Together, etc.)
- **Anthropic** (Claude models)
- **AI Horde** (community fallback, always available)

Automatic key rotation, cost tracking, budget limits.

### Web UI (`web/`)

FastAPI + vanilla JS SPA with 14 panels:
- Overview with health score, AI cost, findings
- Force-directed Brain Map (interactive graph of your codebase)
- Queue management with pause/resume
- Patch review with accept/reject
- Security findings
- Test results
- Guard mode (hosted anomaly alerts)
- Chat with AI about your project
- Settings with provider key management

### Hosted Mode (`core/hosted/`)

Monitor live applications:
- Statistical anomaly detection (Z-score, IQR)
- ML anomaly detection (IsolationForest from scikit-learn)
- IP reputation database with auto-blocking
- Watchlist tracking with time-decay scoring
- 7 log format parsers (nginx, apache, caddy, uvicorn, gunicorn, cloudflare, JSON)
- Daemon mode with auto-restart and health checks

### Learning Brain (`core/brain/learning.py`)

Tracks user accept/reject patterns:
- Bayesian recency-weighted scoring
- Stops suggesting fix types the user always rejects
- Prioritizes fix agents the user trusts
- Data stored in `.patchi/learning.json`

### Git-Aware Intelligence (`core/brain/git_aware.py`)

- Incremental scanning via `git diff`
- Blame integration for tracing findings to commits
- Changelog generation from git log
- Changed-since-last-scan detection

### Shannon Integration (`core/security/pentest/shannon_adapter.py`)

Advanced entropy analysis:
- Detects base64, hex, and custom encoding in payloads
- Identifies encrypted strings and obfuscated code
- Integrates with pentest campaigns for deeper analysis

## Data Storage

All persistent data lives in `.patchi/`:
```
.patchi/
├── config.json          ← Project settings
├── keys.json            ← API keys (gitignored)
├── memory/
│   ├── brain.json       ← Brain scan results
│   ├── patches.json     ← Proposed/applied patches
│   ├── failed_patches.json
│   ├── scan_results.json ← Agent findings
│   ├── known_issues.json
│   ├── restrictions.json
│   └── dev_tokens.json
├── queue.json           ← Task queue
├── snapshots/           ← File rollback snapshots
├── history.json         ← Health score history
├── rejection_counts.json ← User rejection patterns
├── learning.json        ← Accept/reject patterns
├── ast_cache.json       ← File hash cache
└── hosted/
    ├── worker.pid       ← Daemon PID file
    ├── audit_log.jsonl  ← Audit events
    ├── watchlist.json   ← IP threat scores
    └── ip_reputation.json ← Blocklist data
```

## Performance

- **Parallel scanning:** `ProcessPoolExecutor` scales to CPU cores
- **AST caching:** Unchanged files skip re-parsing (MD5 hash comparison)
- **Fix batching:** Different-file agents run in parallel, same-file sequential
- **Incremental scans:** `git diff` detects changed files since last scan
- **File locking:** Cross-platform (msvcrt/fcntl) prevents concurrent corruption
- **Shared atomic writes:** memory.py, snapshot.py, applier.py use shared atomic module

## Security Model

- Keys stored in `.patchi/keys.json`, never in code
- Atomic writes (tmp + rename) prevent data corruption
- Snapshot before every patch apply for rollback
- Risk gate blocks dangerous changes
- Contract protection for critical flows
- `node_modules` and sensitive directories auto-excluded
- External tools documented in `pyproject.toml` `tool.patchi.external_tools`
