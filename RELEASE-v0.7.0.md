# 🛡️ Patchi v0.7.0 — Smart Code Security & Quality Orchestrator

> **Pre-1.0.0 Development Preview** — Functional and usable, but still in active development.
> **Peak stable release is planned for `v1.0.0`** — ~0.4.0 of feature work remains.
> **Feedback appreciated!** Open an issue, start a discussion, or email **idemudiaehis6@gmail.com**.

A CLI agent colony + unified web UI that scans, secures, tests, and fixes your codebase using static analysis and optional AI.
**1:1 CLI ↔ Web** — the web is a fancy wrapper; every screen maps to a command. Cross-platform (Windows, Linux, macOS).

---

## ⚡ Quick Install

```bash
# From source (recommended)
git clone https://github.com/your-username/patchi.git
cd patchi
pip install -e .

# With web UI support
pip install -e ".[web]"

# From PyPI (when published)
pip install patchi
pip install patchi[web]   # with dashboard
```

**Requires Python 3.11+**

---

## 🚀 What's New in v0.7.0

### 🧠 3D Brain Map
Full Three.js-powered 3D code visualization with **8 layout algorithms**:
- **Graph** — Force-directed node layout
- **Tree** — Hierarchical file tree
- **Spiral** — Archimedean spiral by depth
- **Grid** — Uniform grid by severity
- **Radial** — Sunburst from project root
- **Force** — Physics-based spring simulation
- **3D Force** — Three.js force-directed in 3D space
- **3D Sphere** — Spherical projection with orbit controls

**Touch & gesture controls:**
| Gesture | Action |
|---------|--------|
| 1-finger drag | Orbit with momentum |
| 2-finger pinch | Zoom |
| 2-finger twist | Rotate azimuthally |
| 3-finger swipe | Cycle view presets (top/front/side) |
| Double-tap | Reset camera |
| Scroll | Zoom |
| WASD / Arrow keys | Pan |

**Search & compare:**
- Fuzzy search with dropdown results, severity badges, keyboard nav
- Ctrl+Click multi-select for side-by-side node comparison
- Search history (last 10 queries saved to localStorage)
- Ctrl+F or `/` shortcut to focus search from anywhere

### 📊 Gate Timing Intelligence
- **Stacked bar chart** — ruff/pytest/scan execution times over last 20 runs
- **Fast/Full filter** — Toggle between fast (8 core tests) and full (60+ tests) modes
- **Trend line** — 3-point moving average overlay
- **Regression slope indicator** — Shows if gates are getting faster or slower (↑/↓ badge)
- **Hover tooltips** — Per-bar breakdown and trend point details

### 🎬 DAST Video Recording
- Every `p scan --dast` run records video of each page tested via Playwright
- Client-side thumbnail extraction for preview on the Live Tests page
- Multi-viewport baselines: desktop (1440×900), tablet (768×1024), mobile (375×812)

### 🗺️ Assurance Treemap & Heatmap
- Squarified treemap view sized by claim count per domain
- PNG export at 2× resolution for CI/CD dashboards
- Domain detail modal with full claims, evidence, and verdict breakdown

### ⚡ Scan Progress
- Live percentage, current agent name, and spinning gear icon during active scans
- Recent Findings panel refreshes every 5s during scans
- **Cancel All** button + `Ctrl+Shift+X` keyboard shortcut

### 🔧 Dev Check Improvements
- **Fast/Full toggle** — Switch from dashboard without CLI flags
- **History chart** — Canvas-based visualization of gate timing over time
- **Pre-commit hook** — Runs `p dev check` on every commit (ruff + pytest + scan)
- **GitHub Actions CI** — 5 parallel jobs: test, security-scan, dev-check, audit, domain-validation

---

## 🛡️ Security & CLI

- **50 registered CLI commands** — Accurate command table, stale command detection in `p doctor`
- **14 dead commands removed** — brain, chain, explain, health, smart, security, ask, mode, learning, profile, reason, blast, ignore, intent (all merged into existing commands)
- **Performance optimizations** — Lazy-load Konva/Three.js (463KB saved), CSS preload, 24h static asset caching
- **Memory optimizations** — Viewport culling for brain map, reduced canvas redraws, throttled WebSocket events

---

## 🌐 Web UI

- **Unified v2 design** — Single system with panel/card layout across all pages
- **D-Pad navigation** — 8-directional pan controls for brain map
- **Full-screen mode** — Toggle brain map to fill the viewport
- **Toast notifications** — Action feedback for scan/fix/cancel operations
- **Agent status grid** — Auto-refreshing with finding counts
- **Node search highlight** — Matching nodes glow amber, selected node glows white

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [USAGE.md](USAGE.md) | Getting started guide — install, first scan, common workflows |
| [docs/CLI.md](docs/CLI.md) | Complete CLI command reference — all 50 commands with flags |
| [docs/WEB.md](docs/WEB.md) | Web UI guide — pages, controls, keyboard shortcuts, API |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design — directory structure, data flow, key concepts |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow, testing, pre-commit hook |
| [CHANGELOG.md](CHANGELOG.md) | Full changelog with all features since v0.6.0 |

---

## 📊 By the Numbers

| Metric | Value |
|--------|-------|
| CLI commands | 50 |
| Tests | 1,377 (1,374 passing) |
| Brain map layouts | 8 (2D + 3D) |
| Files scanned | 708 |
| Routes detected | 212 |
| Threat scenarios | 17 |
| Commits since v0.6.0 | 135 |

---

## 🏗️ Architecture

```
patchi/
├── cli/commands/          # 50 CLI commands (p scan, p fix, p chat, ...)
├── core/
│   ├── ai/               # LLM orchestrator, tools, providers
│   ├── brain/             # Knowledge graph, council, personas
│   ├── security/          # Domains, agents, charter, auto-fixer
│   └── scanner/           # Multi-language static analysis
├── web/
│   ├── api/               # REST endpoints (HTMX-backed)
│   ├── routes/            # Page handlers (dashboard, findings, ...)
│   ├── templates/         # Jinja2 HTML templates
│   └── static/            # JS (canvas.js, brain3d.js), CSS
└── tests/                 # 1,377 tests
```

---

## 🤝 Contributing

```bash
# Clone and install dev dependencies
git clone https://github.com/your-username/patchi.git
cd patchi
pip install -e ".[dev]"

# Run the pre-commit gate
python -m patchi dev check

# Start the web dashboard
python -m patchi web
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## 📜 License

**Free for personal use and teams under 3 users.**
Enterprise/team licensing: contact **idemudiaehis6@gmail.com**

This is active pre-1.0 software — APIs and behavior may change before v1.0.0.

---

## 🔜 What's Next (→ v1.0.0)

- Comprehensive security domain taxonomy (100+ domains from OWASP, CWE, NIST, SANS)
- Natural language orchestrator (`p chat` as the brain)
- Charter guard rails with auto-rejection of risky fixes
- Visual regression baselines with Playwright
- Proactive auto-fix on file save
- `p doctor --fix` for self-healing configuration

---

**Full changelog:** [CHANGELOG.md](CHANGELOG.md)
**Report issues:** [GitHub Issues](https://github.com/your-username/patchi/issues)
**Email:** idemudiaehis6@gmail.com
