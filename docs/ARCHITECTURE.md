# Patchi Architecture

System design overview for Patchi v0.7.2.

---

## Overview

Patchi is a **CLI agent colony + unified web UI** that scans, secures, tests, and fixes codebases using static analysis and optional AI.

**Design principle:** The web is a fancy wrapper — every screen maps to a CLI command.

```
┌─────────────────────────────────────────────────────┐
│                    User Interface                     │
├──────────────────┬──────────────────────────────────┤
│   CLI (50 cmds)  │   Web UI (FastAPI + Jinja2)      │
├──────────────────┴──────────────────────────────────┤
│                   Core Engine                         │
├──────────┬──────────┬──────────┬────────────────────┤
│  Brain   │  Agents  │  Fixer   │  Security          │
│  (AST,   │  (54     │  (Risk   │  Orchestrator      │
│  graph,  │  agents) │  Gate)   │  (dedup, cross-    │
│  langs)  │          │          │  agent correlation) │
├──────────┴──────────┴──────────┴────────────────────┤
│                 Infrastructure                        │
├──────────┬──────────┬──────────┬────────────────────┤
│  Memory  │  Queue   │  Snapshot│  Notifications     │
│  (JSON)  │  (locked)│  (atomic)│  (Slack, Discord)  │
└──────────┴──────────┴──────────┴────────────────────┘
```

---

## Directory Structure

```
patchi/
├── cli/                    # Command-line interface
│   ├── main.py             # Root parser, lazy imports
│   ├── framework.py        # Command registration framework
│   ├── registry.py         # All 50 registered commands
│   ├── console.py          # Rich console output
│   └── commands/           # One file per command (48 files)
│
├── core/
│   ├── brain/              # AST scanning, import graph, language detection
│   │   ├── brain.py        # Brain class — main orchestrator
│   │   ├── scanner.py      # File discovery and scanning
│   │   ├── languages.py    # Language support (20+ via tree-sitter)
│   │   ├── layered_brain.py # Layered architecture analysis
│   │   ├── charter.py      # Project guard rails
│   │   └── ast_utils/      # AST manipulation utilities
│   │
│   ├── agents/             # Agent framework
│   │   ├── base.py         # BaseAgent, Finding, Severity, register()
│   │   ├── coordinator.py  # Multi-agent orchestration
│   │   ├── governor.py     # Phase-gated state machine
│   │   └── cache.py        # Tree-sitter parse cache
│   │
│   ├── security/           # 54 security agents
│   │   ├── orchestrator.py # Cross-agent correlation
│   │   ├── security_agents.py # Agent registry
│   │   ├── injection_agent.py # SQLi, XSS, command injection
│   │   ├── dast_agent.py   # Dynamic application testing
│   │   └── ...             # 50+ specialized agents
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
└── tests/                  # 1,377 tests
```

---

## Data Flow

### Scan Pipeline

```
p scan
  → Brain scans files (tree-sitter parsing)
  → Import graph built
  → 54 security agents run in parallel
  → Findings deduplicated by orchestrator
  → Cross-agent correlation (exploit chains)
  → Results stored in .patchi/memory/
  → BRAIN.md auto-generated
  → Health score computed
```

### Fix Pipeline

```
p fix
  → RiskGate assesses each finding
  → AI generates fix candidates
  → Safety checks (no data loss, no new vulns)
  → User approval (confirm mode) or auto-apply
  → Patches applied atomically
  → Verify loop re-checks fixes
  → Snapshot taken for rollback
```

### Web Request Flow

```
Browser → FastAPI → Route handler → Core engine → JSON/HTML
                ↕
         WebSocket (real-time scan progress)
```

---

## Key Concepts

### Brain
The Brain is the central knowledge store. It:
- Discovers files and builds an import graph
- Detects languages via file extensions + tree-sitter
- Analyzes project structure (layers, domains, routes)
- Generates `BRAIN.md` with plain-English project summary
- Tracks health scores across dimensions

### Agent Colony
54 security agents run as independent workers:
- Each agent specializes in one vulnerability class
- Agents are lazy-loaded (only run when needed)
- Circuit breakers prevent runaway agents
- The Governor orchestrates agent phases
- The Orchestrator deduplicates and correlates findings

### Risk Gate
Every fix goes through the Risk Gate:
- Assesses change risk (file importance, test coverage, blast radius)
- Blocks dangerous changes (no tests, production config, etc.)
- Allows safe changes (comments, formatting, low-risk imports)
- Supports three modes: confirm, auto, autopilot

### Charter
Project-specific guard rails:
- NL parser converts rules into structured constraints
- Violations surface as findings
- Governor escalation prevents risky changes
- Drift detection catches unauthorized modifications

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| CLI | argparse + Rich |
| Web framework | FastAPI + Jinja2 + HTMX |
| Brain map | Konva.js (2D) + Three.js (3D) |
| AST parsing | tree-sitter (20+ languages) |
| Security tools | Semgrep CE, Gitleaks, OSV-Scanner, httpx |
| AI providers | OpenAI, Anthropic, Google, Groq, Mistral, + 10 more |
| Testing | pytest + Playwright |
| CI/CD | GitHub Actions |
| Package management | pip + pyproject.toml |

---

## Concurrency Model

- **CLI:** Synchronous with async internals (asyncio)
- **Web:** Async FastAPI with WebSocket for real-time updates
- **Agents:** Parallel execution with bounded concurrency
- **Queue:** File-locked for crash-safe persistence
- **Memory:** Atomic writes via temp file + rename

---

## Security Model

- API keys stored in `.patchi/keys.json` (never sent elsewhere)
- Hosted mode marked EXPERIMENTAL
- Tenant isolation via `tenant_context`
- API endpoints require `X-API-Key` header
- Pre-commit hook validates before every commit
