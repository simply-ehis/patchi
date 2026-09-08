# Patchi Web UI

The unified Patchi web dashboard — a full-featured Mission Control for your codebase.

**Launch:** `p web` → http://127.0.0.1:1612

---

## What Makes It Special

Patchi's web UI isn't just a dashboard — it's a **1:1 CLI mirror**. Every screen maps to a command. Every action has a CLI equivalent. The web is a fancy wrapper; the CLI is the engine.

### Capabilities

| Capability | Description |
|------------|-------------|
| **Real-time scan progress** | WebSocket-powered live updates — agent name, percentage, findings as they appear |
| **Interactive Brain Map** | 2D/3D code visualization with 8 layout algorithms, search, multi-select, comparison |
| **One-click operations** | Scan, fix, DAST, stress test, dev check — all from the dashboard |
| **Video evidence** | DAST sessions recorded with Playwright, viewable in-browser |
| **Visual regression** | Multi-viewport baselines with diff comparison |
| **Assurance heatmap** | Coverage visualization with treemap and grid views |
| **Agent monitoring** | Live agent status, performance stats, learning patterns |
| **Threat model evolution** | Track how your security posture changes over time |
| **Health scoring** | 0-100 score with A-F grade across security, tests, deps, dead code |
| **Cost tracking** | AI provider usage, token counts, budget alerts |
| **Multi-project** | Switch between projects from the dashboard |
| **Export** | JSON, CSV, PNG for CI/CD and reporting |

---

## Pages

### Dashboard (`/`)

The main overview with three panels:

#### Brain Map (left)
Interactive visualization of your project's file structure.

**8 Layout Algorithms:**

| Layout | Description |
|--------|-------------|
| Graph | Force-directed node layout |
| Tree | Hierarchical file tree |
| Spiral | Archimedean spiral by depth |
| Grid | Uniform grid by severity |
| Radial | Sunburst from project root |
| Force | Physics-based spring simulation |
| 3D Force | Three.js force-directed in 3D space |
| 3D Sphere | Spherical projection with orbit controls |

**Controls:**
- **Mouse:** Scroll to zoom, drag to pan, right-drag to rotate
- **Touch:** Pinch to zoom, swipe to pan
- **3D mode:** Orbit (1 finger), zoom (pinch), rotate (2-finger twist), presets (3-finger swipe)
- **Search:** Click the search bar or press `/` or `Ctrl+F`
- **Multi-select:** Ctrl+Click nodes to compare side-by-side
- **Keyboard:** `↑↓` navigate matches, `Enter` selects, `Escape` clears

**Node colors:**
- Green: Clean (no findings)
- Yellow: Medium severity
- Orange: High severity
- Red: Critical severity
- Blue glow: Selected for comparison

#### Quick Actions (right)
Buttons for common operations:

| Button | Action |
|--------|--------|
| **Scan Project** | Run a full scan |
| **Fix Issues** | Apply auto-fixes |
| **Run DAST** | Dynamic application security testing |
| **Stress Test** | Load testing |
| **Dev Check** | Run the 3-gate CI check (ruff + pytest + scan) |

Each button shows a progress indicator while running and a cancel button (or `Ctrl+Shift+X` for all).

#### Recent Findings (bottom)
Table of latest findings with severity, type, file, and agent columns.

- Auto-refreshes every 30s (5s during active scans)
- Click a finding to see details
- Export as JSON

---

### Findings (`/findings`)

Complete list of all security findings.

**Tabs:**
- **All Findings** — Every finding from all agents
- **By Severity** — Grouped by critical/high/medium/low/info
- **Chain Claims** — Findings linked to exploit chains
- **Charter Violations** — Rules broken by code

**Filtering:**
- Search by filename, type, or agent
- Filter by severity, type, or agent
- Sort by any column

**Export:**
- **JSON** — Machine-readable for CI/CD
- **CSV** — Spreadsheet-compatible

---

### Assurance (`/assurance`)

Coverage heatmap and claim verification.

**Heatmap Views:**
- **Grid** — Traditional tile grid, colored by coverage %
- **Treemap** — Tiles sized by claim count per domain

**Controls:**
- **Search** — Filter domains by name
- **Sort** — By coverage, name, or claim count
- **Export PNG** — Download the heatmap as a high-res image

**Domain Details:**
Click any tile to see:
- All claims with evidence and verdicts
- Coverage breakdown (proved/total)
- Related findings

**Trend Line:**
Historical coverage % over time with snapshot history.

---

### Live Tests (`/live-tests`)

Browser test recordings and visual regression evidence.

**Video Recordings:**
- Thumbnail previews with duration badges
- Click to play recorded test sessions
- Recorded automatically during DAST scans

**Visual Regression:**
- Baseline screenshots at desktop (1440×900), tablet (768×1024), mobile (375×812)
- Comparison view showing diffs
- Pass/fail status per page

**Smoke Test:**
Run a quick smoke test from the browser:
1. Click **Run Smoke Test**
2. Wait for Playwright to capture all pages
3. Review screenshots and video

---

### Self-Improvement (`/self-improvement`)

Agent profiles, learning summary, and threat model evolution.

**Agent Profiles:**
- Performance stats per agent (accuracy, latency, findings)
- Accept/reject ratios
- Learning patterns

**Learning Summary:**
- What the system has learned from your project
- Pattern recognition results
- Conventions discovered

**Threat Model:**
- Evolving threat scenarios
- Coverage per scenario
- Historical changes

---

### Doctor (`/doctor`)

System health and stale command detection.

**Checks:**
- Stale commands detected with replacement suggestions
- Missing dependencies
- API key configuration
- `.patchi/` size warnings
- Config validation

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `/` or `Ctrl+F` | Focus brain map search |
| `↑↓` | Navigate search results |
| `Enter` | Select search match |
| `Escape` | Clear search / exit full-screen |
| `Ctrl+Shift+X` | Cancel all running operations |
| `F` | Toggle full-screen brain map |

---

## WebSocket Events

The dashboard receives real-time updates via WebSocket:

| Event | Description |
|-------|-------------|
| `scan.started` | Scan initiated |
| `scan.progress` | Scan progress update (agent name, percentage) |
| `scan.complete` | Scan finished |
| `scan.finding` | New finding discovered |
| `scan.cancelled` | Scan cancelled |

---

## API Endpoints

All web features are backed by REST APIs:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Run a scan |
| `/api/fix/apply-all-safe` | POST | Apply safe fixes |
| `/api/dev-check` | POST | Run dev check gate |
| `/api/dev-check/history` | GET | Gate timing history |
| `/api/brain-map` | GET | Brain map nodes and edges |
| `/api/agents/status` | GET | Agent status grid |
| `/api/live-testing/videos` | GET | Video recordings |
| `/api/live-testing/video/{file}` | GET | Serve video file |
| `/health` | GET | Health endpoint for load balancers |

---

## Design System

The web UI uses a consistent design system:

- **Panels** — Card containers with header, content, and optional actions
- **Buttons** — Primary (accent), secondary (ghost), danger (red)
- **Typography** — Inter for UI, JetBrains Mono for code/monospace
- **Colors** — CSS custom properties (`--accent`, `--bg-card`, `--text-primary`, etc.)
- **Spacing** — 4px grid system
- **Transitions** — 0.15s ease for hover states

---

## Multi-Project Support

```bash
p web --project ../other-repo     # Scan a different project
p web --port 8000                 # Custom port
p web --open                      # Auto-open browser
```

---

## Related Documentation

- [CLI Reference](CLI.md) — All 60 commands
- [Architecture](ARCHITECTURE.md) — System design
- [Deployment](DEPLOYMENT.md) — Hosted mode setup
- [Overview](OVERVIEW.md) — Technical overview
