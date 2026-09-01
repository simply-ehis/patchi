# Patchi Web UI Guide

The unified Patchi web dashboard — launched with `p web`.

---

## Launching

```bash
p web                     # Default: http://127.0.0.1:1612
p web --port 8000         # Custom port
p web --open              # Auto-open browser
p web --project ../other  # Scan a different project
```

---

## Dashboard (`/`)

The main overview with three panels:

### Brain Map (left)
Interactive visualization of your project's file structure.

**Views:** Graph | Tree | Spiral | Grid | Radial | 3D

**Controls:**
- **Mouse:** Scroll to zoom, drag to pan, right-drag to rotate
- **Touch:** Pinch to zoom, swipe to pan
- **3D mode:** Orbit (1 finger), zoom (pinch), rotate (2-finger twist), presets (3-finger swipe)
- **Search:** Click the search bar or press `/` or `Ctrl+F`
- **Multi-select:** Ctrl+Click nodes to compare
- **Keyboard:** `↑↓` navigate matches, `Enter` selects, `Escape` clears

**Node colors:**
- Green: Clean (no findings)
- Yellow: Medium severity
- Orange: High severity
- Red: Critical severity
- Blue glow: Selected for comparison

### Quick Actions (right)
Buttons for common operations:

| Button | Action |
|--------|--------|
| **Scan Project** | Run a full scan |
| **Fix Issues** | Apply auto-fixes |
| **Run DAST** | Dynamic application security testing |
| **Stress Test** | Load testing |
| **Dev Check** | Run the 3-gate CI check |

Each button shows a progress indicator while running and a cancel button (or Ctrl+Shift+X for all).

### Recent Findings (bottom)
Table of latest findings with severity, type, file, and agent columns.

- Auto-refreshes every 30s (5s during active scans)
- Click a finding to see details
- Export as JSON

---

## Findings (`/findings`)

Complete list of all security findings.

### Tabs
- **All Findings** — Every finding from all agents
- **By Severity** — Grouped by critical/high/medium/low/info
- **Chain Claims** — Findings linked to exploit chains
- **Charter Violations** — Rules broken by code

### Filtering
- Search by filename, type, or agent
- Filter by severity, type, or agent
- Sort by any column

### Export
- **JSON** — Machine-readable for CI/CD
- **CSV** — Spreadsheet-compatible

---

## Assurance (`/assurance`)

Coverage heatmap and claim verification.

### Heatmap Views
- **Grid** — Traditional tile grid, colored by coverage %
- **Treemap** — Tiles sized by claim count per domain

### Controls
- **Search** — Filter domains by name
- **Sort** — By coverage, name, or claim count
- **Export PNG** — Download the heatmap as a high-res image

### Domain Details
Click any tile to see:
- All claims with evidence and verdicts
- Coverage breakdown (proved/total)
- Related findings

### Trend Line
Historical coverage % over time with snapshot history.

---

## Live Tests (`/live-tests`)

Browser test recordings and visual regression evidence.

### Video Recordings
- Thumbnail previews with duration badges
- Click to play recorded test sessions
- Recorded automatically during DAST scans

### Visual Regression
- Baseline screenshots at desktop/tablet/mobile viewports
- Comparison view showing diffs
- Pass/fail status per page

### Smoke Test
Run a quick smoke test from the browser:
1. Click **Run Smoke Test**
2. Wait for Playwright to capture all pages
3. Review screenshots and video

---

## Self-Improvement (`/self-improvement`)

Agent profiles, learning summary, and threat model evolution.

### Agent Profiles
- Performance stats per agent (accuracy, latency, findings)
- Accept/reject ratios
- Learning patterns

### Learning Summary
- What the system has learned from your project
- Pattern recognition results
- Conventions discovered

### Threat Model
- Evolving threat scenarios
- Coverage per scenario
- Historical changes

---

## Doctor (`/doctor`)

System health and stale command detection.

### Checks
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

---

## Design System

The web UI uses a consistent design system:

- **Panels** — Card containers with header, content, and optional actions
- **Buttons** — Primary (accent), secondary (ghost), danger (red)
- **Typography** — Inter for UI, JetBrains Mono for code/monospace
- **Colors** — CSS custom properties (`--accent`, `--bg-card`, `--text-primary`, etc.)
- **Spacing** — 4px grid system
- **Transitions** — 0.15s ease for hover states
