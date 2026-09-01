# Changelog

## [0.7.0] - 2026-09-01

### 🚀 New Features
- **3D Brain Map** — Full Three.js-powered 3D visualization with orbit controls, momentum physics, pinch-to-zoom, two-finger rotate, three-finger swipe presets, and double-tap reset
- **8 Brain Map Layouts** — Graph, Tree, Spiral, Grid, Radial, Force, 3D Force, 3D Sphere — all with interactive controls
- **Brain Map Search** — Fuzzy matching with dropdown results, severity badges, keyboard navigation (↑↓/Enter), Ctrl+F shortcut, search history (last 10 saved to localStorage)
- **Multi-Select Comparison** — Ctrl+Click nodes in search dropdown to compare multiple files side-by-side
- **Gate Timing Chart** — Stacked bar chart showing ruff/pytest/scan execution times over last 20 runs, with Fast/Full filter toggle, trend line (moving average), and linear regression slope indicator
- **DAST Video Recording** — Every `p scan --dast` run automatically records video of each page tested via Playwright VideoRecorder
- **Video Thumbnails** — Client-side frame extraction for video preview thumbnails on the Live Tests page
- **Multi-Viewport Baselines** — `p vr baseline` captures at desktop (1440×900), tablet (768×1024), and mobile (375×812)
- **Assurance Treemap** — Squarified treemap view for the heatmap, sized by claim count per domain
- **Assurance Export PNG** — Export the heatmap grid as a downloadable PNG at 2× resolution
- **Scan Progress Enhancement** — Live percentage, current agent name, and spinning gear icon during active scans
- **Findings Fast-Refresh** — Recent Findings panel updates every 5s during active scans (same as agent grid)
- **Bulk Cancel** — Cancel All button + Ctrl+Shift+X keyboard shortcut to abort all running operations
- **Dev Check Fast/Full Toggle** — Switch between fast (8 core tests, ~18s) and full (60+ tests, ~130s) modes from the dashboard
- **Dev Check History Chart** — Canvas-based chart showing gate timing history with hover tooltips
- **Search History Dropdown** — Shows last 10 searches with time-ago labels when focusing empty search input
- **3D Brain Map Legend** — Explains node size scaling, severity colors, and health overrides

### 🛡️ Security & CLI
- **Command Audit & Cleanup** — Removed 14 dead/superseded command files (brain, chain, explain, health, smart, security, ask, mode, learning, profile, reason, blast, ignore, intent)
- **50 registered commands** — Accurate command table in README, stale command detection in `p doctor`
- **Performance Optimizations** — Lazy-load Konva/Three.js (463KB saved on non-brain pages), CSS preload, static asset caching with 24h TTL
- **Memory Optimizations** — Viewport culling for brain map, reduced canvas redraws, throttled WebSocket events

### 🌐 Web UI
- **Unified Web Dashboard** — v2 design as single system, panel/card layout with consistent styling across all pages
- **D-Pad Navigation** — 8-directional pan controls for brain map (WASD + arrow keys)
- **Full-Screen Mode** — Toggle brain map to fill the entire viewport
- **Node Search Highlight** — Matching nodes highlighted with amber glow, selected node with white glow
- **Toast Notifications** — Action feedback for scan/fix/cancel operations
- **Progress Bars** — Animated gradient progress bars for scan, DAST, and stress test operations
- **Agent Status Grid** — Auto-refreshing grid showing all agent last-run status with finding counts
- **Domain Detail Modal** — Rich expandable view with full claims, evidence, and verdict breakdown

### 🔧 Developer Experience
- **GitHub Actions CI** — 5 parallel jobs: test (matrix 3.11/3.12), security-scan, dev-check, audit, domain-validation
- **Pre-commit Hook** — Runs `p dev check` gate (ruff + pytest + scan) on every commit with warnings-only mode
- **Cleanup Command** — `p cleanup` removes stale `.patchi/` artifacts (JUnit XML, caches, logs, DBs) with `--older-than` and `--json` flags
- **Doctor Stale Detection** — Identifies 14 merged/removed commands with replacement suggestions
- **30 Stray Files Removed** — Cleaned up temp scripts, debug output, and server logs from project root

### 📊 Stats
- 50 registered CLI commands (14 dead files removed)
- 1,377 tests (1,374 passing, 3 skipped)
- 708 files scanned, 212 routes, 17 threat scenarios
- 3 brain map view modes (2D + 3D) with 8 layout algorithms
- 135 commits since v0.6.0

---

## [0.6.0] - 2026-08-26

### 🚀 New Features
- **`p dev check`** — 3-gate CI check (ruff + pytest + scan) with JSON output and JUnit parsing
- **`p dev hook --strict`** — Pre-commit hook that blocks commits on lint/test failures
- **`p ask`** — Natural language queries against the layered brain (what changed, what imports, hotspots)
- **`p charter`** — Project guard rails system with NL parser and drift detection
- **`p assure`** — Assurance commands: `--chain-report`, `--run-attackers`, `--run-campaigns`
- **`p chains --fix`** — Auto-apply fixable remediations from exploit chains via RiskGate
- **Multi-language remediation** — Go, Java, Rust, PHP, Ruby patterns for 6 key finding types
- **Remediation confidence scoring** — Based on auto-fix capability, language match, and fix acceptance rates
- **Cost threshold alerts** — Dashboard warning when AI spending exceeds configurable budget

### 🛡️ Security
- **Charter guard rails** — NL parser converts rules into structured guard rails; violations surface as findings
- **Chain explorer cross-linking** — Findings link to exploit chains and vice versa
- **Tenant isolation** — `tenant_context` wraps scan/fix/assurance handlers for per-project isolation
- **API key auth** — CI/CD endpoints require `X-API-Key` header with auto-generated key
- **CI audit script** — Comprehensive `scripts/ci-audit.sh` (agent audit, ruff, mypy, fast tests)

### 🌐 Web UI
- **Fixed scan buttons** — Security scan and report buttons now produce results
- **Scan result refresh** — Findings and severity counts auto-update after scan completes
- **Before/after comparison** — Finding comparison cards for scan diffing
- **Chain claims tab** — Exploit chain visualization with remediation suggestions
- **Charter violations tab** — Displays charter rule violations in findings page

### 🔧 CLI Improvements
- `p dev hook` now shows current mode (strict/warn-only) when installed
- `p scan --quiet` flag added to suppress non-essential output
- Charter violations display in scan output
- Debug adapters (node/python/powershell) return proper responses instead of raising errors
- `tools/run_full_suite.py` for blocking full test suite execution

### 🏗️ Infrastructure
- **Tree-sitter parse cache** shared across agents with bounded memory
- **Lazy torch import** in gnn_models.py (prevents test collection slowdown)
- **ruff format** cleanup across 308 files
- Comprehensive `.gitignore` rules for runtime artifacts
- Debug adapters (node/python/powershell) fixed to return dict instead of NotImplementedError

### 📊 Stats
- 62 CLI commands
- 164+ tests passing
- 40+ security agents
- 14 web route files
- 23 fuzz/attacker/campaign/reliability modules
