# Changelog

## [0.7.2] - 2026-09-02

### 🧠 Understander-First Brain (Slices 1-6)
- **L1 Enriched Context — 1 LLM/scan** `brain/enriched_context.py` `ProjectInsight+StackInfo+layers` → `brain.json:enriched_context {purpose_1sent, domain, domain_confidence, tech_stack_confirmed, critical_dirs_reasoned, top_risks[3], scan_focus}` 1s timeout, `PATCHI_OFFLINE` heuristic fallback
- **L2 AIConfidenceGate** `security/confidence_gate.py:201` second pass only `low + (high/critical OR secret/injection/auth)` capped 10 findings via `AIValidator 3-step code→data flow→exploitability` `{verdict, reason, exploitability}` offline `unverified`
- **L3 RAG Reasoning** `brain/reasoning.py:179` was `re.findall` bag → TF-IDF `tf*idf + body_tags boost` over cached `layers[].summary` built at scan `brain.py:635 rag_index` stored `layers.json`, `ask(ask_ai=True)` wraps RAG + `call_ai`
- **L4 Council Memo** `brain/council.py:410` `SHA256(issue+context)[:16]` `council_cache.json` 7-day TTL prune 50
- **Body Tags + Understander** `brain/body_tags.py` `brain/understander.py` `core_files(16) score=fan_in*10+dep*3` replaces `file_infos[:50]` insertion order, `contract.py:269` + `brain.py:446` gated `body_tags.json {role: brain/muscle/bone/blood/skin/nerve}`
- **Tool-Reading LLM** `ai/tools/read_file 500 lines/3 calls` `realize.py:995` validated `≤2MB`, wired `fix/base function_at`, `AIValidator`, `council`
- **Real Pentest Registry** `security/pentest/` `nuclei/sqlmap/dalfox/ffuf/zap` `shannon_adapter Option 2 external npx` `shannon` AGPL-clean via `npx @keygraph/shannon start -u {target} -r {repo}` parsing `*.sarif`, `attack_simulate(use_real_tools,use_shannon)` `realize.py:420` + `red_team_engine _run_pentest_tool` `aio.to_thread`, `ai_pick` shannon-aware
- **Fix/Test Context** `fix/base.py:229` `function_at` + `blast_radius dependents[:3]`, `realize generate_tests auto` → `Understander.untested_core()` `realize.py:1026`, `gate scanners` via `body_tags is_route_file high/critical` `realize.py:262` `182→~40` Flask
- **Quality:** `0 bare except` prod (AST 103→0), `patchi/cli scan_cmd:767 unmatched )` fix, `reasoning ffuf/zap` debug logs, `py_compile` all, `pytest 73` pass, `Brain.scan patchi/core/brain 75 files 18s`

---

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
