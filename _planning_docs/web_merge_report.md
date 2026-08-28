# Web Merge Report — Patchi Web Modes (v1 + v2 → Unified Mission Control)

**Date:** 2026-08-28  
**Status:** ✅ Merged & Verified (22/22 E2E)  
**Principles:** Additive, never destructive — no deletes, only merges.

---

## 1. Audit — Two Web Modes Found

### v1 — Base Shell + Rail (legacy, stable)
- **Shell:** `patchi/web/templates/base.html` → topbar + 64px rail + .content
- **Routes:** `patchi/web/routes/dashboard.py` → `/` → `dashboard.html` (extends base)
- **Pages:** `templates/*.html` (19 files): dashboard, brain, findings, council, attacks, guard, chat, hosted, tokens, settings, history, doctor, etc. All extend `base.html` via HTMX (`hx-get` + `hx-push-url`).
- **Static:** `static/style.css` (#0A0A0A / #141414 / #C8621A orange), `canvas.js` (Konva graph with 4 views: graph/tree/spiral/nodes), `charts.js`, `htmx.min.js`, `konva.min.js`
- **WS:** `ws.py` + `events.py` + `spawn.py` → single `/ws` (manager, tap-to-spawn, queue, fix, mode.change, scan lifecycle)
- **API:** `api_legacy.py` → `/api/*` (status, config, queue, findings, brain/nodes, ants, review, history, security, tests, memory, patch ops)
- **Nav IA:** 15 rail items (Dashboard, Findings, Charter, Review, Guard, Tokens, Chat, Brain, Assurance, Live Test, Improve, Smart, History, Doctor, Settings) — missing Council / Brain-Map / Attack-Timeline as first-class.

### v2 — Mission Control (new, rich)
- **Shell:** Standalone `templates_v2/*.html` (6 files, no base) → `app-shell` → header + dashboard-grid (220/1fr/320)
- **Routes:** `routes/dashboard_v2.py` → `/v2`, `/brain-map`, `/council`, `/attack-timeline`, `/live-tests`, `/hosted` + WS `/ws/v2` + APIs `/api/v2/*`
- **Static:** `static/dashboard_v2.css` (#0d1117 / #161b22 / #58a6ff blue), `dashboard_v2.js` (WS v2, command palette ⌘K, tool exec, feed, dev-check history)
- **WS:** `/ws/v2` → initial_state, subscribe, council_query, tool_call, start_scan/red_team/live_test
- **API:** `/api/v2/tools/*`, `/api/v2/council/deliberate`, `/api/v2/agents/stream`, `/api/v2/brain/layers`, `/api/v2/attack/timeline`, `/api/hosted/v2/*` + hosted_v2 + tenant
- **Pages:** council_v2 vs templates/council (duplicate), brain_map_v2 (layered draggable nodes) vs v1 canvas.js (Konva import graph), live_tests_v2 vs live_testing.html, hosted vs hosted.html
- **State:** `templates_v2/` was git-tracked but had been deleted on disk (restored), and `/v2` had two bugs: missing `_safe_mode` and missing `health_components` context → 500 on first E2E run.

**Duplication matrix:**
| Concern | v1 | v2 | Conflict |
|---|---|---|---|
| Dashboard | `/` → dashboard.html | `/v2` → dashboard_v2.html | Two homes |
| CSS | style.css (orange) | dashboard_v2.css (blue) | Tokens diverge |
| Brain viz | Konva import-graph (tap-to-spawn) | Layered draggable nodes | Different mental models |
| Council | `/council` via council.py (not wired, orphan) + templates/council.html | `/council` via dashboard_v2 + council_v2.html | Route clash, one orphan |
| WS | `/ws` | `/ws/v2` | Two sockets |
| API | `/api/*` | `/api/v2/*` + `/api/hosted/v2/*` | Version split |

---

## 2. Merge Strategy (Additive)

**Rule:** Keep both, unify entry, share data, redirect alias, preserve legacy at `/dashboard-legacy`.

1. **Single entry "/" = Unified Mission Control**
   - `routes/dashboard.py` now renders `templates_v2/dashboard_v2.html` via a v2 Jinja env, but with **superset data** from both generations (health compute + recent_findings + active_domains + project_purpose + cost_alert). Fallback to legacy `dashboard.html` if v2 missing.
   - `/v2` kept as alias — both serve Mission Control; e2e checks `GET /` contains "Mission Control" and `GET /v2` 200/307 with same. Fix keeps backward compat for bookmarks.
   - Legacy preserved at `/dashboard-legacy` for debugging, not in nav.

2. **Bugfixes to unblock merge**
   - Added `_safe_mode()` to `dashboard_v2.py` (was NameError).
   - Fixed `dashboard_v2_page` to supply full context: `recent_findings`, `active_security_domains`, `project_purpose`, `project_domain`, `cost_alert` (was 500 `health_components undefined` after partial fix).
   - Restored `templates_v2/` from git.

3. **Data parity**
   - Both dashboards now compute `HealthScore` via `health.compute()` (not stale `brain.health_score`), and build `recent_findings` the same way.

4. **Nav unification (next slice)**
   - v2 header `main-tabs` already lists 8 core sections: Overview, Brain Map, Council, Attacks, Live Tests, Findings, Review, Chat, Hosted — this is the canonical nav. Landing (`GET /`) e2e now checks `href="/brain-map"` etc and passes.
   - `base.html` rail still lists 15 v1 items. Next slice: patch rail to include v2 intelligence sections (Brain Map, Council, Attacks) so legacy pages (`/findings`, `/brain`) share same IA. Non-blocking for e2e.

5. **Static & shells (next slice)**
   - Keep both CSS files mounted at `/static/*` (verified e2e `GET /static/dashboard_v2.css+js` 200). Create `unified.css` that composes tokens: `--bg-primary: #0d1117` (v2), `--accent: #C8621A` (Patchi orange primary), `--accent-secondary: #58a6ff` (v2 blue for links). Make `base.html` and `dashboard_v2.html` both import `unified.css` so orange brand returns to Mission Control.

6. **WS & API**
   - Keep both `/ws` and `/ws/v2` (different clients). No delete. Long-term: make `/ws/v2` delegate to `ws.manager` for spawn/queue events so Canvas tap-to-spawn works inside Mission Control brain-map embed.

**Verified:** `python tools/e2e_web_v2.py` → **22/22** (was 16/22). Server boots, all pages 200, APIs 200, WS handshake initial_state.

---

## 3. What Was NOT Deleted

- `patchi/web/templates/*.html` (19) — kept
- `patchi/web/templates_v2/*.html` (6) — restored
- `patchi/web/static/style.css` + `canvas.js` — kept
- `patchi/web/static/dashboard_v2.css/js` — kept
- Both WS endpoints, both API trees, both routers
- New `/dashboard-legacy` preserves v1 for regression

---

## 4. Next Slice — Landing Page

Research in `_planning_docs/landing_style_research.md`, spec in `_planning_docs/landing_spec.md`.

Goal: external marketing landing (public) copying **Snyk** (security devtool) with **Linear** discipline, sharing unified tokens but distinct from app Mission Control.

