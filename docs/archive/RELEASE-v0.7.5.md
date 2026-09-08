# Patchi v0.7.5 Release Notes

> **Pre-1.0.0 Development Preview** — Functional and usable, still in active development.
> **Peak stable release is planned for v1.0.0** — ~0.4.0 of feature work remains.

---

## What's New in v0.7.5

### CLI UX Module (`patchi/cli/ux.py`)

A complete UI toolkit for the CLI:
- `spinner()` — Context-managed Rich spinners with status messages
- `progress_bar()` — Multi-phase progress bars with task tracking
- `LiveStatus` — Real-time status display for long operations
- `result_table()` — Formatted Rich tables for findings and results
- `summary_panel()` — Summary panels with key metrics
- `CountdownTimer` — Animated countdown for timed operations
- `status_icon()` / `colored_status()` — Visual status indicators
- `format_header()` / `format_error()` / `format_success()` / `format_warning()` / `format_info()` — Consistent formatting
- `confirm()` / `select()` — Interactive prompts

Applied to: `ready_cmd`, `commands_cmd`, `scan_cmd`, `test_cmd`, `fix_cmd`

### Quick Readiness Check (`p quick`)

Fast project health validation:
- Runs 3 lightweight agents in seconds
- Spinners + progress indicators
- Clear pass/fail output
- No AI tokens required

### Interactive Fix Review (`p fix-review`)

Enhanced patch review experience:
- Accept/reject/skip per patch
- Inline diff view with syntax highlighting
- Batch operations (accept all, reject all)
- Filter by finding type

### Command Families (`p <family> commands`)

Discover commands by category:
- 24 families: scan, fix, test, agent, ai, config, web, charter, notify, hosted, git, dev, queue, brain, vr, goal, cross-repo, etc.
- `p scan commands` lists all scan-related commands
- `p fix commands` lists all fix-related commands

### Shannon Integration

Advanced entropy analysis for pentest campaigns:
- Detects base64, hex, and custom encoding
- Identifies encrypted strings and obfuscated code
- Integrated into `PentestRegistry` and `attack_simulate` tool
- External tool health checks in `tool_health.py`

### Dependency Consolidation

All runtime dependencies now in main:
- Web: fastapi, uvicorn, jinja2, websockets
- Testing: playwright, Pillow, aiohttp, pixelmatch
- AI/ML: scikit-learn
- Security: pymetasploit3
- AST: tree-sitter + 18 language packs

Optional extras:
- `dev`: pytest, ruff, mypy, vulture
- `pentest`: shannon

---

## Bug Fixes

### Critical (7 production bugs fixed)

| File | Line | Issue | Fix |
|------|------|-------|-----|
| `risk_gate.py` | 199 | TypeError on missing attribute | Added null check |
| `risk_gate.py` | 332 | KeyError on missing key | Added `.get()` with default |
| `queue.py` | 283 | TypeError on None comparison | Added type guard |
| `memory.py` | 279 | AttributeError on missing attr | Added null check |
| `applier.py` | 189 | TypeError on None input | Added validation |
| `codeql_agent.py` | 233 | Exception on missing binary | Added graceful fallback |
| `health.py` | 142-152 | Division by zero | Added zero-check |

### Test Fixes

| File | Line | Issue | Fix |
|------|------|-------|-----|
| `test_domain_loader.py` | 345 | Mock not patched correctly | Fixed mock path |
| `test_generated_suite.py` | 132-141 | Flaky assertion | Fixed expected values |
| `test_new_agents.py` | — | Missing gate mock | Added `@patch` for `require_ready` |
| `test_differential.py` | — | Timing issue | Added sleep tolerance |
| `test_domain_loader.py` | 460 | Missing fixture | Added test data |
| `test_test_agents.py` | — | Gate not mocked | Added gate mock |

### Architectural Fixes

- `patchi/core/atomic.py` — Shared atomic write module
- `memory.py` / `snapshot.py` / `applier.py` — Shared atomic operations
- `coordinator.py` — Cache invalidation on agent updates
- `scan_bus.py` — Deterministic sharding for consistent results

---

## By the Numbers

| Metric | v0.7.2 | v0.7.5 |
|--------|--------|--------|
| CLI commands | 54 | 60 |
| Command families | — | 24 |
| Security agents | 54 | 125 |
| Security domains | 800 | 800 |
| Playbooks | 2,955 | 2,955 |
| Tests | 1,300+ | 1,000+ |
| Tree-sitter languages | 18 | 20+ |
| AI providers | 14 | 14 |
| External tools | 4 | 6+ |

---

## Documentation

- **README.md** — Complete overhaul: version bump, stats update, cleaner structure
- **docs/ARCHITECTURE.md** — Updated directory structure, data flow, key concepts
- **docs/CLI.md** — Updated command count, new commands (quick, fix-review, status, ready)
- **docs/OVERVIEW.md** — Updated agent counts, added pentest/shannon section
- **docs/DEPLOYMENT.md** — No changes (hosted mode docs stable)
- **docs/WEB.md** — No changes (web UI docs stable)

---

## Breaking Changes

- **None** — all changes are additive or internal fixes

---

## Upgrading

```bash
# From source
git pull
pip install -e ".[dev,web]"

# From PyPI (when published)
pip install --upgrade patchi
```

No migration needed. `.patchi/` memory format is forward-compatible.

---

## What's Next (→ v1.0.0)

- Full domain taxonomy (100+ domains from OWASP, CWE, NIST, SANS)
- Natural language orchestrator (`p chat` as the brain)
- Charter guard rails with auto-rejection of risky fixes
- Visual regression baselines with Playwright
- Proactive auto-fix on file save
- `p doctor --fix` for self-healing configuration

---

**Report issues:** [GitHub Issues](https://github.com/simply-ehis/Patchi/issues)
**Email:** idemudiaehis6@gmail.com
