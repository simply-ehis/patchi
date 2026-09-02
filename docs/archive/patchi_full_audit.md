# Patchi v0.6.0 — Full Codebase Audit vs Specification

> **Audited**: 2026-06-30 (updated)
> **Specification sources**: `files 6/` — 17 documents including BUILD_PLAN.md, patchi_build_spec_final.md, patchi_supplementary_spec.md, patchi_complete_plan.md, patchi_planning_decisions.md, patchi_overview.md, 01–07 planning docs, 1782754697561-crisp-otter.md, SHIP_CHECKLIST.md
> **Codebase**: `c:\Users\ehis\Desktop\Patchi\` (v0.6.0)
> **Test result**: 764 collected, 58 passed (scanner tests), **2 collection errors** blocking ~100+ tests

---

## Table of Contents

1. [Critical Bugs](#1-critical-bugs)
2. [What's Done Wrong](#2-whats-done-wrong)
3. [What's Missing vs Specs](#3-whats-missing-vs-specs)
4. [What Needs to Be Changed](#4-what-needs-to-be-changed)
5. [Core Issues & Logic Limitations](#5-core-issues--logic-limitations)
6. [Suggested Upgrades](#6-suggested-upgrades)
7. [New Since Last Audit — BUILD_PLAN Progress](#7-new-since-last-audit--build_plan-progress)
8. [SHIP_CHECKLIST Status](#8-ship_checklist-status)

---

## 1. Critical Bugs

### BUG-01: Dual Web Architecture Causes Import Crash (SEVERITY: BLOCKER)

> [!CAUTION]
> This bug makes `server.py`, `test_web.py`, and `test_integration.py` completely unusable. Two test files fail to even **collect**, blocking ~100+ tests from running.

The codebase has **two conflicting web API implementations** that shadow each other:

| File | Type | Lines | Used By |
|---|---|---|---|
| `api.py` | Monolithic module (2,021 lines) | Exports `router`, `_root()` | `server.py`, test files |
| `api/__init__.py` | Empty package (2 lines) | Exports **nothing** | `app.py` (CLI entry) |

**What happens**: Python resolves `import patchi.web.api` to the **package** (`api/__init__.py`), not the module (`api.py`). Since `__init__.py` is empty, every `from patchi.web.api import router` raises `ImportError`.

**Crash chain**:
```
test_integration.py:12 → from patchi.web.api import _root     → ImportError
test_web.py:24         → from patchi.web.server import create_app
  server.py:30         → from patchi.web.api import router     → ImportError
```

The CLI works only because `web_cmd.py` imports from `patchi.web.app` (package-based API). `server.py` is **dead code** — it can never be imported. All web/integration tests are broken.

---

### BUG-02: Duplicate `BrainMap` Global Variable (SEVERITY: HIGH)

Two JavaScript files define the **exact same** global constant `BrainMap`:

| File | Lines | Architecture |
|---|---|---|
| `brain-map.js` | 499 | 4-layer Konva (nodeLayer, edgeLayer, antLayer, labelLayer), force-directed layout |
| `canvas.js` | 879 | 2-layer Konva (nodeLayer, antLayer), mini-map, zoom controls |

Both begin with `const BrainMap = (() => { ... })()`. The second silently fails on load (can't re-declare `const`). `dashboard.html` does **not** include either script. `base.html` calls `window.BrainMap.handleEvent` but never loads the script. The Brain Map **never renders** in the live web UI.

> **New finding (1782754697561-crisp-otter.md)**: The Web UI Rebuild spec defines octagonal nodes via Konva.js with a 4-layer canvas (nodeLayer, edgeLayer, antLayer, labelLayer). The spec in `patchi_build_spec_final.md` requires HTML Canvas (not SVG). Neither existing JS file matches the spec's octagonal grid node design with 7 distinct node colors. `brain-map.js` uses the closest approach (4 layers, force-directed) but the node shape is circular, not octagonal.

---

### BUG-03: Duplicate WebSocket / Event Systems (SEVERITY: HIGH)

Three separate event/WebSocket systems exist:

| File | Manager Class | Used By |
|---|---|---|
| `events.py` (427 lines) | `ConnectionManager` | `server.py` (dead code) |
| `ws.py` (106 lines) | `WSManager` (dataclass) | `app.py` (live), `api/scan.py` |
| `base.html` inline JS | Client-side `new WebSocket()` | htmx templates |

`events.py` defines typed helpers (`evt_agent_started`, `evt_scan_complete`, `evt_ant_spawned`) that `test_web.py` tests against. But the live `app.py` imports `ws.py`, which has a completely different API. Test suite tests `events.py`, running app uses `ws.py`.

---

### BUG-04: Duplicate `/api/findings` Route (SEVERITY: MEDIUM)

Two files register GET `/api/findings`:
- `api.py` line 184 — returns `JSONResponse`
- `api/scan.py` line 73 — returns `HTMLResponse` (Jinja2 template)

Since `app.py` mounts the `scan_router`, the HTML version wins. Any client expecting JSON gets broken HTML instead.

---

### BUG-05: `app.py` Never Initializes `SpawnManager` or Cost Tracker (SEVERITY: MEDIUM)

`server.py` sets `app.state.spawner = SpawnManager(root)` and calls `init_cost(root)`. The live `app.py` sets `app.state.root` but **never creates a SpawnManager or initializes cost tracking**. Any endpoint accessing `app.state.spawner` crashes with `AttributeError`. Any `/api/status` endpoint referencing `get_stats()` returns zeroes.

---

### BUG-06: `_chat_history` Is Module-Level Unbounded In-Memory List (SEVERITY: MEDIUM)

`api_chat.py` line 29: `_chat_history: list[dict] = []` grows unbounded with no cap, no persistence, and no per-session isolation. The spec calls for chat history saved in `.patchi/memory/`. This is a memory leak in a long-running server.

---

### BUG-07: `blame_line()` Parses Porcelain Format Incorrectly (SEVERITY: LOW)

`git_aware.py` `blame_line()` looks for lines starting with `"commit "` in porcelain output. Git porcelain blame outputs the hash as the **first token** with no prefix. The function always returns `None` for the commit field.

---

### BUG-08: WebSocket Handler Is a No-Op (SEVERITY: HIGH) — NEW

`app.py` lines 65–73: the WebSocket `receive_text()` result is stored in `data` and then **never read**. No action routing, no spawn handling, no queue commands. The spec requires tap-to-spawn, queue pause/resume, and fix accept/reject over WebSocket. `server.py` had `_handle_client_event()` for this but is dead code.

---

### BUG-09: `security_agents.py` Exports Internal Helpers in `__all__` (SEVERITY: LOW) — NEW

`security_agents.py` `__all__` includes `_run`, `_call_ai`, `_call_ollama`, `_call_openai_compat` — private helper functions from `security_config.py`. These should not be in `__all__`. Any code doing `from patchi.core.security.security_agents import *` will import these implementation details, creating an unstable public API surface.

---

## 2. What's Done Wrong

### WRONG-01: Two Parallel Web Architectures Were Never Unified

The codebase evolved through at least two major refactors:

1. **Architecture A** (`server.py` + `api.py` + `events.py`): Monolithic 2,021-line API, rich typed `ConnectionManager`, `SpawnManager`. Written for by the test suite.
2. **Architecture B** (`app.py` + `api/` package + `ws.py` + `routes/`): Modular routers, htmx-based, what the CLI actually uses.

Architecture B was built without removing Architecture A. The `api/` package directory shadows `api.py`, breaking all imports targeting the old module.

---

### WRONG-02: `api/scan.py` Hardcodes Agent Names Instead of Using Registry

`api/scan.py` lines 33–42 hardcodes a `_DEFENSIVE` list of 19 agent names. `security_agents.py` registers **34 agents** dynamically via `@register`. The hardcoded list silently skips 15 agents on every web-triggered security scan.

---

### WRONG-03: `_run_file_scan` Deep Flag Is Always True

`scan_cmd.py` line 321: `if deep or True:` — `or True` makes the `deep` flag meaningless. Every `--file` scan burns AI tokens for deep analysis even when the user didn't request it.

---

### WRONG-04: `learning.py` Only Tracks Fixes, Not Explanations

`learning.py` tracks accept/reject patterns for fixes via `record_acceptance` / `record_rejection`. But the spec (`07_EHIS_VISION_PLAN.md`) describes `p explain` as teachable — user corrections should feed back into the Brain. `explain_cmd.py` never calls `record_acceptance` or `record_rejection`. The correction loop doesn't exist.

---

### WRONG-05: Brain Map Spec vs Implementation Mismatch

The `1782754697561-crisp-otter.md` doc defines the Brain Map node design as **octagonal** with 7 specific color states, force-directed layout with entry points at top and dead files at bottom, and a 4-layer Konva canvas. `brain-map.js` uses circular nodes and `canvas.js` uses a grid layout. Neither matches the spec. `dashboard.html` doesn't load either script.

---

### WRONG-06: `GovernanceAgent` Walks Entire File Tree on Every Security Scan (SEVERITY: MEDIUM) — NEW

`governance.py` `GovernanceAgent._run()` calls `safe_rglob(inp.root, "*")` — it walks **every file** in the project to check never_touch policy patterns. This runs during every security scan and is O(n) over all files. For large projects, this is wasteful. It should only check files that were touched in the current fix cycle.

---

### WRONG-07: `PolicyEngineAgent` Loads All Source Files Per Policy Rule (SEVERITY: MEDIUM) — NEW

`policy_engine.py` `PolicyEngineAgent._run()` iterates all source files for every policy pack rule, resulting in O(files × rules × packs) iterations. With 4 built-in packs × 4 rules × N files, this creates excessive I/O on every security scan. Should batch per-file, not per-rule.

---

### WRONG-08: `SecurityTestAgent` Generates Flask-Specific Fixtures for All Frameworks (SEVERITY: MEDIUM) — NEW

`security_test_agent.py` `_generate_tests()` generates test boilerplate that hardcodes `from flask import Flask` in the pytest fixture, regardless of the target project's framework. A FastAPI or Django project will get Flask fixtures that won't run. Should use `app_contract.framework` to generate the correct fixture.

---

### WRONG-09: Install Scripts Don't Install `dev` Dependencies by Default (SEVERITY: LOW) — NEW

`install.sh` and `install.ps1` call `pip install -e ".[dev]"` which assumes a `[dev]` extras section exists in `pyproject.toml`. If the user only runs the plain script on a project that doesn't have dev extras defined, the install silently falls back to base dependencies. There's no verification that pytest and ruff were actually installed.

---

## 3. What's Missing vs Specs

### MISS-01: Onboarding Wizard — CLI and Web (patchi_complete_plan.md, 07_EHIS_VISION_PLAN.md)

The spec calls for:
- `p init` (no prompts) — silently sets AI Horde as default, prints a warm one-line message
- `p init --guided` — interactive flow for power users
- Web UI: 5-screen onboarding modal on first visit

`config.py` has `"onboarding_complete": False` but **no UI, CLI flow, or template** ever reads or acts on this flag. `init.py` asks questions on every run instead of defaulting silently.

---

### MISS-02: VS Code Extension (07_EHIS_VISION_PLAN.md)

Fully specified: status bar indicator, inline diagnostics (squiggly underlines), command palette integration, Patchi sidebar panel, `extensions/vscode/` directory structure with 7 TypeScript files. **No VS Code extension code exists anywhere in the repository.**

---

### MISS-03: `p explain` Teachable Mode (07_EHIS_VISION_PLAN.md)

`explain_cmd.py` (282 lines) exists and calls AI. But the spec requires a correction loop: user corrects an explanation → stored in `.patchi/learning.json` → used next time. The learning module exists but `explain_cmd.py` never calls it.

---

### MISS-04: Git Hash-Based Incremental Scanning (07_EHIS_VISION_PLAN.md)

`git_aware.py` has `get_changed_files()`. `freshness.py` checks staleness by timestamp. But `Brain.scan()` always walks all files. The deep scan path in `scan_cmd.py` uses MD5 hashes to skip unchanged files — but this logic is not in the regular scan path at all.

---

### MISS-05: Hosted Mode WebSocket Log Streaming (05_HOSTED_MODE_IMPROVEMENT_PLAN.md)

Plan specifies: stream log lines over WebSocket in real-time, IP geolocation, severity classification, incident lifecycle (detected → investigating → confirmed → mitigated → resolved), real-time metrics chart, auto-blocking rules. `guard.html` is a static template. `api/hosted.py` only has `/status`, `/block/{ip}`, `/unblock/{ip}`. No streaming, no geolocation, no metrics dashboard.

---

### MISS-06: Quiet Hours Not Enforced (patchi_complete_plan.md)

Config keys `quiet_hours_start`, `quiet_hours_end`, `quiet_hours_timezone` are defined but **no code checks them** before running scans or sending notifications. The `quiet_hours.py` module exists in `core/notifications/` but is never called from scan or fix pipelines.

---

### MISS-07: Settings Panel in Web UI (patchi_complete_plan.md, 1782754697561-crisp-otter.md)

No `/settings` route, no settings template, no way to configure Patchi from the browser. The nav has: Dashboard, Findings, Review, Guard, Chat, Brain — no Settings. The spec calls for 8 settings tabs (General, AI and Models, Scan, Fix, Constraints, Notifications, Brain, Queue, Advanced).

---

### MISS-08: History Panel Missing from Web UI (patchi_complete_plan.md)

The spec defines Panel 5 (History) as a health score line graph over time with tappable data points, filter controls, and per-session diffs. The `history.py` module now records scan history to SQLite but the web UI has no `/history` route, no history template, and no chart reading from this table.

---

### MISS-09: Weekly Health Report Email (patchi_complete_plan.md, patchi_supplementary_spec.md)

Both specs explicitly describe a weekly email report — "every Monday morning, plain English, one page." The notification system (`channels.py`, `digest.py`) exists but there is no scheduled job, no cron entry, no `p report --email`, and no weekly report template.

---

### MISS-10: Diff Viewer in Review Panel (patchi_complete_plan.md, 1782754697561-crisp-otter.md)

`review.html` shows patch metadata (description, file, risk score, confidence) with Apply/Reject buttons but **no actual diff content**. Users cannot see what a patch changes before accepting it. The spec calls for a side-by-side color-coded diff with syntax highlighting.

---

### MISS-11: Health Score Trend Chart (patchi_complete_plan.md)

`health.py` computes a score from current state but **never writes it to history**. `charts.py` reads from a SQLite `scan_history` table (finding counts + severity breakdown) but health scores are absent. The "Health score over time" graph on the Overview panel has no data to display.

Now that `history.py` tracks scan history, it needs to be updated to also record the health score per scan so the chart can render it.

---

### MISS-12: `p blame` and `p log` Commands (07_EHIS_VISION_PLAN.md)

The vision plan specifies:
- `p blame src/api/users.py:42` — shows which commit introduced a finding
- `p log --since "last week"` — auto-generated changelog of Patchi activity

Neither command exists in the CLI. `git_aware.py` has `blame_line()` (though broken per BUG-07) and `get_changed_files()` which could power these commands.

---

### MISS-13: `p audit plan` Command (BUILD_PLAN.md Phase 7)

`plan_auditor.py` and `PlanAuditorAgent` exist and are registered. But `audit_cmd.py` in the CLI doesn't expose a `p audit plan <spec-file>` command. The agent can only be run via `p security` (which includes all agents). There's no dedicated `p audit` path.

---

### MISS-14: `p deps` Command (BUILD_PLAN.md Phase 4)

`supply_chain.py` and `SupplyChainAgent` exist with `--sbom`, `--licenses`, `--outdated` conceptual flags. But there's no `p deps` CLI command. The supply chain scan only runs as part of the full security sweep.

---

### MISS-15: Detect-Fix-Verify Loop (BUILD_PLAN.md Phase 2)

The plan specifies: after `SecurityFixer` applies a patch, re-run the same scanner agent that found the issue, verify the finding is gone, retry up to 2 times. `security_fixer.py` applies patches but **does not re-scan to verify the fix worked**. The loop described in BUILD_PLAN.md Phase 2 is not implemented.

---

### MISS-16: SARIF Export (03_APP_UPGRADE_PLAN.md)

`p scan --format sarif` would enable GitHub Code Scanning, GitLab SAST, Azure DevOps integration. `report_cmd.py` exports markdown and JSON but not SARIF. No SARIF serializer exists.

---

### MISS-17: GitHub App / PR Bot (07_EHIS_VISION_PLAN.md)

Fully specified: GitHub App that posts scan results as PR comments, sets commit status checks, can push fix commits to PR branches in Auto mode. **Nothing exists.** No webhook handler, no GitHub API client, no PR comment logic.

---

### MISS-18: Cross-Project Dashboard (07_EHIS_VISION_PLAN.md)

Described as the eventual SaaS product: all projects in one view, fix debt metric, team health comparison, daily Slack digest. No infrastructure for this exists. Noted as Month 3+ in the vision plan but listed here for completeness.

---

## 4. What Needs to Be Changed

### CHANGE-01: Unify Web Architecture — Delete Architecture A

**Action**: Delete `server.py`, `api.py` (monolith), and `events.py`. Keep `app.py` + `api/` package + `ws.py` + `routes/`. Then port from the dead files into `app.py`:
- `SpawnManager` initialization from `server.py`
- `_handle_client_event()` WebSocket action routing from `server.py`
- `init_cost(root)` cost tracker initialization from `server.py`
- Update `api/__init__.py` to re-export anything still needed
- Update `test_web.py` and `test_integration.py` to import from `app.py`

This single change unblocks ~100+ tests and eliminates BUG-01 through BUG-05 simultaneously.

---

### CHANGE-02: Unify Brain Map JavaScript

**Action**: Keep `canvas.js` (879 lines, more features: mini-map, zoom controls) and delete `brain-map.js`. Ensure `dashboard.html` includes `<script src="/static/canvas.js">`. Then update `canvas.js` node shapes from circles to octagons per the `1782754697561-crisp-otter.md` spec, and wire the 7 node color states to file health status.

---

### CHANGE-03: Fix `api/scan.py` to Use Dynamic Agent Registry

Replace the hardcoded `_DEFENSIVE` list:
```python
from patchi.core.agents.base import list_agents, AgentGroup
to_run = [a for a in list_agents(AgentGroup.SECURITY)]
```
This ensures all 34 registered agents run, not just the 19 hardcoded.

---

### CHANGE-04: Fix `blame_line()` Porcelain Parsing

The first line of `git blame --porcelain` is `<hash> <orig-line> <final-line> <count>`. No `"commit "` prefix. Update the parser to extract the first whitespace-delimited token as the hash.

---

### CHANGE-05: Cap `_chat_history` and Persist It

- Add `MAX_HISTORY = 200` cap to `api_chat.py`
- Persist to `.patchi/memory/chat_history.json` on append
- Load on startup
- Add per-session key if multi-user is ever needed

---

### CHANGE-06: Wire Quiet Hours into Scan and Notification Pipelines

Add `is_quiet_hours(config) -> bool` that reads `quiet_hours_start`, `quiet_hours_end`, `quiet_hours_timezone` and returns True/False. Call it:
- Before auto-triggered scans (watch mode)
- Before sending Level 3 and Level 4 notifications via `notifier.py`

The `quiet_hours.py` module in `core/notifications/` may already have this logic — wire it in.

---

### CHANGE-07: Add Diff Content to Review Cards

In `routes/review.py`, load the `diff` field from each patch object and pass it to the template. In `review.html`, render it in a `<pre><code class="diff">` block with diff syntax highlighting (add `diff2html` or a simple CSS-only unified diff renderer).

---

### CHANGE-08: Remove `or True` from `_run_file_scan`

`scan_cmd.py` line 321: change `if deep or True:` to `if deep:`. Straightforward one-word fix.

---

### CHANGE-09: Wire Health Score into Scan History

In `health.py` `compute()`, after calculating the score, call `patchi_record_scan()` from `history.py` with the score included (extend the schema or add a `health_score` column to `scan_history`). This feeds the history chart on the Overview panel.

---

### CHANGE-10: Remove Private Helpers from `security_agents.py` `__all__`

Remove `_run`, `_call_ai`, `_call_ollama`, `_call_openai_compat` from the `__all__` list in `security_agents.py`. These are implementation details of `security_config.py` and should not be exported from the security agents module.

---

### CHANGE-11: Fix `SecurityTestAgent` to Use Project Framework for Fixtures

In `security_test_agent.py`, read `inp.brain.get("framework", "")` and generate the appropriate test client fixture:
- Flask → `from flask import Flask; app = Flask(__name__); return app.test_client()`
- FastAPI → `from fastapi.testclient import TestClient; from app import app; return TestClient(app)`
- Django → `from django.test import Client; return Client()`
- Unknown → generate a `requests.Session()` HTTP client targeting `localhost`

---

### CHANGE-12: Add `p deps` CLI Command

Create `patchi/cli/commands/deps_cmd.py` that runs `SupplyChainAgent` and `CVEMonitorAgent` with flags `--sbom`, `--licenses`, `--outdated`. Register in `main.py`. This surfaces the supply chain work built in BUILD_PLAN Phase 4.

---

### CHANGE-13: Implement Detect-Fix-Verify Loop

After `SecurityFixer` applies a patch in `fix_agents.py` / `applier.py`, re-run the specific scanner that produced the finding:
```python
re_result = agent_class(brain, scope, config).run()
still_present = any(f.file == finding.file and f.line == finding.line for f in re_result.findings)
if still_present and retry_count < 2:
    # retry with different prompt
```
Mark the fix as `verified` only when the re-scan confirms the finding is gone.

---

## 5. Core Issues & Logic Limitations

### LIMIT-01: Brain Scan Always Rescans Everything

`Brain.scan()` walks the entire file tree on every call. Despite `git_aware.py` and `freshness.py` existing, the main scan path never uses them to skip unchanged files. The freshness check in `scan_cmd.py` only prevents re-running the scan entirely if the brain is "fresh" — it doesn't do incremental scanning. On a 5,000-file project, every `p scan` re-parses everything.

---

### LIMIT-02: Fix Agent Batching Logic Is Dead Code

`coordinator.py` `_run_fix_agents_batched()` groups agents by target file, but **no fix agent implements `target_files()`**. The `getattr(cls, "target_files", None)` check always returns `None`, so every agent lands in `ungrouped` and runs in parallel anyway. The batching logic that was meant to prevent same-file conflicts is never invoked.

---

### LIMIT-03: LLM Agent Reordering Happens on Every Scan with No Caching

`coordinator.py` `_maybe_reorder()` calls the LLM on **every scan** to ask which agents to prioritize. This decision almost never changes between runs. There is no caching of the reorder result. Potential fix: cache the reorder result keyed by `(agent_set_hash, brain_framework)` and invalidate only when agents or framework change.

---

### LIMIT-04: No Per-Agent Internal Timeout or Watchdog

The coordinator sets a 120-second `future.result(timeout=120)` for scanner agents at the thread level. But if an agent hangs internally (e.g., tree-sitter parse on a 50MB generated file), the thread is blocked until the OS kills it. No per-agent watchdog, no kill signal, no graceful degradation.

---

### LIMIT-05: Security Scan via Web UI Has No Progress Feedback

`api/scan.py` fires scans via `asyncio.create_task()` and calls `evt_scan_progress` on `ws.py`. But `app.py`'s WebSocket handler never sends the current status to newly-connected clients. A client connecting mid-scan receives nothing until the next event fires. The `server.py` version had `_push_status()` on connect — that logic needs to be ported.

---

### LIMIT-06: Health Score Has No Persistence History

`health.py` computes the score from current state but never saves historical scores. `charts.py` reads from a `scan_history` SQLite table that has finding counts but no health score column. The Overview panel's "Score over time" chart has no data.

---

### LIMIT-07: `p explain` Has No Context Windowing

`explain_cmd.py` sends the entire finding context to the AI in a single call. For large files or complex findings this can exceed the model's context window. No chunking, no summarization, no fallback to a smaller prompt.

---

### LIMIT-08: `SecurityOrchestrator` Deduplication Key Is Too Narrow — NEW

`orchestrator.py` deduplication groups findings by `(file, line, type)`. But two agents can report the same vulnerability at different line numbers (e.g., `TaintAnalyzer` reports the sink line, `InjectionAgent` reports the source line). These are not deduplicated and both appear in the `SecurityReport`, artificially inflating the finding count. Should also group by `(file, type, cwe)` with a configurable line-tolerance window.

---

### LIMIT-09: `SupplyChainAgent` License Check Only Works for Files Already on Disk — NEW

`supply_chain.py` `_check_license()` tries to read license info from `package.json` or `pyproject.toml` — but the file path it receives is the dependency file's relative path, not the installed package's metadata. For `requirements.txt` dependencies, it looks for a `pyproject.toml` in the same directory, which is the project's own `pyproject.toml`, not the dependency's. License checking is effectively broken for PyPI packages. Should use `pip show <pkg>` or the PyPI JSON API for accurate license data.

---

### LIMIT-10: `CVEMonitorAgent` Has No Local Cache — NEW

`cve_monitor.py` `_check_osv()` makes an HTTP request to the OSV API for **every dependency on every scan**. For a project with 100 dependencies, this fires 100 network requests. No caching, no rate limiting, no batch query. The OSV API supports batch queries (`POST /v1/querybatch`). Should batch all dependencies in one request and cache results with a TTL.

---

### LIMIT-11: `PreCheckAgent` Lint Check Silently Fails When Ruff Is Not Installed — NEW

`prechecks.py` `patchi_lint_check()` wraps `ruff` via subprocess. If ruff isn't installed, `FileNotFoundError` is caught silently and an empty list is returned. The scan proceeds as if linting passed. Should log a warning or add an info-level finding when the linter binary isn't found.

---

### LIMIT-12: `E2EFlowAgent` Hardcodes Port Scan for Local Server — NEW

`e2e_flow_agent.py` `_find_base_url()` tries ports `[3000, 5173, 8080, 4200, 8000, 4321]` to find a running server. If the project runs on any other port (e.g., 9000, 1337), the agent silently skips all tests with "no running server found." Should read the project config or `p web` port setting as the first candidate.

---

## 6. Suggested Upgrades

### UPGRADE-01: Unified Web Architecture with Hot Reload (🔴 Critical)

Merge the best of both architectures into a single `app.py`:
- Keep the modular `api/` package router structure
- Port `SpawnManager`, cost tracking, and WebSocket action routing from `server.py`
- Replace `ws.py` with the richer `events.py` event system (typed dicts, proper schemas)
- Add `--reload` flag to `p web` for development hot-reload via `uvicorn --reload`
- Update all test imports to target `app.py`

---

### UPGRADE-02: Incremental Brain Scan with Content Hashing (🟡 High)

The MD5 hashing pattern exists in `_run_deep_scan_analysis()`. Promote it to the main scan path:
- Store `{file_path: md5_hash}` in brain data after each scan
- On next scan, skip files whose hash hasn't changed
- Combine with `git_aware.get_changed_files()` as a fast pre-filter
- Expected speedup: 5–10x on large codebases with few changes

---

### UPGRADE-03: Agent Result Caching (🟡 High)

Cache agent results keyed by `(agent_name, file_content_hash, config_hash)`:
- Store in `.patchi/cache/agent_results/`
- Add `--no-cache` flag to force fresh analysis
- Cuts AI costs significantly and eliminates the LLM reorder waste (LIMIT-03)
- Already partially solved by the AST cache in `.patchi/ast_cache.json`

---

### UPGRADE-04: Settings Panel in Web UI (🟡 High)

Add a `/settings` route and template per `patchi_build_spec_final.md` Section 9 Panel 10:
- 8 tabs: General, AI and Models, Scan, Fix, Constraints, Notifications, Brain, Queue, Advanced
- Toggle switches for boolean config keys
- API key management with masked display
- All changes via `POST /api/config`

---

### UPGRADE-05: Diff Viewer with Syntax Highlighting (🟡 High)

Replace plain-text review cards with a proper diff viewer:
- Use `diff2html` JS library (MIT, 20KB) for side-by-side or unified diff rendering
- Add syntax highlighting per language via Prism.js or highlight.js
- Show blast radius badge (files affected by the change)
- "Preview in context" button that shows the patched file in full

---

### UPGRADE-06: WebSocket Reconnection with Exponential Backoff (🟢 Medium)

`base.html` does: `ws.onclose = () => { setTimeout(() => location.reload(), 3000); }` — reloads the entire page on disconnect, losing all UI state.

Replace with exponential backoff (1s → 2s → 4s → 8s → max 30s) that reconnects without a page reload. Add a visible "Reconnecting…" indicator in the top bar.

---

### UPGRADE-07: Per-Agent Timeout and Circuit Breaker (🟢 Medium)

Add configurable timeouts per agent group:
- Scanners: 60s default
- Security agents: 90s default
- Fix agents: 120s default

Circuit breaker: if an agent fails 3 times in a row, mark it `circuit_broken` in memory, skip it on future runs, log the pattern. Reset via `p agents reset <name>`.

---

### UPGRADE-08: Onboarding Wizard — CLI and Web (🟢 Medium)

Implement the two-path onboarding spec from `patchi_complete_plan.md` Section 10:

**CLI path** (`p init` — no prompts):
1. Auto-detects framework
2. Sets AI Horde as default silently
3. Prints: "🐜 Patchi is watching your project. Run `p scan` to start."
4. Exits

**CLI guided path** (`p init --guided`): current interactive flow

**Web path**: 5-screen modal on first visit (`onboarding_complete: false`):
1. Welcome — one headline, one sentence
2. Pick surface (CLI/Web/Hosted)
3. Add AI (4 options + privacy note)
4. Three features
5. Done + "Run first scan" button

---

### UPGRADE-09: OSV Batch Query and CVE Cache (🟢 Medium)

`CVEMonitorAgent` makes one HTTP request per dependency. Fix by:
- Using OSV `/v1/querybatch` endpoint to query all deps in a single request
- Caching results in `.patchi/cache/cve_cache.json` with a 24-hour TTL
- Expected improvement: 100+ HTTP requests → 1 request per scan

---

### UPGRADE-10: SARIF Export for CI/CD Integration (🟢 Medium)

Add `p scan --format sarif` to output findings in [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) format. Enables:
- GitHub Code Scanning integration
- GitLab SAST integration
- Azure DevOps integration
- Any SARIF-compatible tool

The `Finding` dataclass has all required fields (file, line, severity, type, message, cwe).

---

### UPGRADE-11: `p explain` Learning Loop (🟢 Medium)

After AI generates an explanation in `explain_cmd.py`, ask: "Was this explanation helpful? [y/n/correct it]". On "correct it", capture the correction and call `record_acceptance` / `record_rejection` in `learning.py` with the explanation type. Use stored corrections to prepend context to future AI calls for the same finding type.

---

### UPGRADE-12: History Panel in Web UI (🟢 Medium)

Add `/history` route and `history.html` template:
- Health score line graph over time (reads from `patchi_history.db` `scan_history` table once CHANGE-09 is done)
- Each data point tappable — shows what changed that session in a slide-in panel
- Filter by date range, action type, outcome
- Per-session undo available

---

### UPGRADE-13: Plugin Architecture for Custom Agents (🔵 Low)

Allow `.patchi/plugins/agents/*.py` — any file defining a class extending `BaseAgent` is auto-registered on startup. Lets teams add project-specific scanners without forking Patchi. The `@register` decorator system already supports this; just needs a discovery loop in `coordinator.py`.

---

### UPGRADE-14: Public Status Page (🔵 Low — Hosted Mode)

Per `patchi_supplementary_spec.md` Section 6 Feature 6: off by default, enable in hosted settings. Generates a public page at a subdomain or custom URL showing uptime percentage, last 90 days incident history, current active incidents. Updates automatically when Patchi detects an issue.

---

## 7. New Since Last Audit — BUILD_PLAN Progress

The `BUILD_PLAN.md` defined 14 implementation phases. Here's what was built and what's still open:

### Phase 0: Register Unregistered Agents ✅ COMPLETE

All 7 previously-unregistered agents are now imported in `security_agents.py`:
`InjectionAgent`, `AuthZAgent`, `CryptoAgent`, `NetworkAgent`, `PrivacyAgent`, `DependencyVulnerabilityAgent`, `ComplianceAgent`

Total registered security agents: **34** (up from 13 previously).

> **Gap**: The `__all__` list in `security_agents.py` includes internal helpers (`_run`, `_call_ai`, `_call_ollama`, `_call_openai_compat`) — see BUG-09.

---

### Phase 1: Security Orchestrator ✅ COMPLETE

`orchestrator.py` implements `SecurityOrchestrator.correlate()`:
- Deduplication by `(file, line, type)` key
- Multi-agent correlation with `confirmed_by` list
- Composite risk scoring (severity weight + confirmation bonus)
- OWASP Top 10 2021 mapping via CWE lookup
- `SecurityReport` dataclass with `by_severity` and `by_owasp` summaries

> **Gap (LIMIT-08)**: Dedup key is too narrow — agents reporting the same vulnerability at different lines aren't merged. Should add a line-tolerance window.
> **Gap**: `SecurityOrchestrator` is not yet called from `Coordinator.run_all_security_agents()`. It exists as a standalone class but nothing calls `orch.correlate(results)` in the scan pipeline.

---

### Phase 2: Detect-Fix-Verify Loop ❌ NOT IMPLEMENTED

`security_fixer.py` applies patches. No re-scan gate exists. See MISS-15 and CHANGE-13.

---

### Phase 3: Secrets Guard ✅ COMPLETE

`secrets_guard.py` implements:
- `scan_code_for_secrets()` — regex-based scanner for 8 secret pattern types
- `gate_check_proposed_code()` — pre-apply gate for patches (but not yet wired into `risk_gate.py`)
- `SecretsGuard` agent registered for config/CI/Docker/K8s file scanning

> **Gap**: `gate_check_proposed_code()` is implemented but not called from `risk_gate.py` or `applier.py`. The pre-apply gate doesn't actually block secret-introducing patches yet.

---

### Phase 4: Supply Chain Security ✅ COMPLETE

`supply_chain.py` implements `SupplyChainAgent`:
- Levenshtein-based typosquatting detection against 30 popular package names
- License compliance (copyleft detection for GPL/AGPL/LGPL)
- Dependency pinning validation (flags `*`, `latest`, `>=0`)
- Supports: npm, pip, pyproject.toml, Cargo.toml, go.mod, Gemfile, composer.json

> **Gap (LIMIT-09)**: License checking only works for `package.json` and `pyproject.toml` files on disk. For `requirements.txt` deps, it searches the wrong path. PyPI license metadata needs `pip show` or the PyPI JSON API.
> **Gap (MISS-14)**: No `p deps` CLI command exposes this agent directly.

---

### Phase 5: Security Test Auto-Generation ✅ COMPLETE

`security_test_agent.py` implements `SecurityTestAgent`:
- Generates per-route pytest files in `tests/security/`
- Tests: auth bypass, SQLi, XSS, CSRF (POST/PUT/PATCH/DELETE only), CORS, rate limiting
- Saves to `tests/security/test_security_<route>.py`

> **Gap (WRONG-08)**: Generates Flask-specific fixtures for all frameworks.
> **Gap**: Tests are generated but `p test security` command doesn't exist in `test_cmd.py` to run them.

---

### Phase 6: Runtime Validation ✅ COMPLETE (Partial)

`runtime_validator.py` registered as `RuntimeValidatorAgent`. Checks live HTTP responses for security headers and TLS configuration.

> **Gap**: Full OWASP ZAP DAST integration and Docker sandbox described in BUILD_PLAN Phase 6 are not implemented. `RuntimeValidatorAgent` does HTTP header checks only.

---

### Phase 7: Plan-Auditing Engine ✅ COMPLETE

`plan_auditor.py` implements `PlanAuditorAgent`:
- Checks all expected security agents are imported
- Checks CLI commands exist
- Checks new modules exist
- Checks test coverage for new modules
- Checks health score wiring

> **Gap (MISS-13)**: No `p audit plan <spec-file>` CLI command. `PlanAuditorAgent` only runs as part of a full security sweep.

---

### Phase 8: IaC and Container Security ✅ COMPLETE (Registered)

`iac_scanner.py` → `IaCScannerAgent` and `container_scanner.py` → `ContainerScannerAgent` are registered.

> **Gap**: Integration with Checkov and Trivy binaries (described in BUILD_PLAN) is not confirmed. Need to verify these modules actually invoke external tools vs doing regex-only checks.

---

### Phase 9: Security Policy Engine ✅ COMPLETE

`policy_engine.py` implements `PolicyEngineAgent`:
- Built-in policy packs: SOC2, HIPAA, PCI-DSS, CIS
- Custom YAML/JSON policies from `.patchi/policies/`
- 10 check types: `no_default_credentials`, `no_plaintext_http`, `has_logging`, etc.

> **Gap (WRONG-07)**: O(files × rules × packs) iteration. Should batch per-file.
> **Gap**: No `p security --policy soc2` flag in `security_cmd.py` to run a specific policy pack.

---

### Phase 10: Continuous Security Monitoring ✅ COMPLETE (Partial)

`cve_monitor.py` implements `CVEMonitorAgent`:
- Queries OSV API per dependency
- Supports npm (`package.json`) and PyPI (`requirements.txt`)

> **Gap (LIMIT-10)**: No batch query, no local cache. 100 deps = 100 HTTP requests per scan.
> **Gap**: `p monitor start` background daemon described in BUILD_PLAN doesn't exist.

---

### Phase 11: Red Team / Adversarial ✅ COMPLETE (Partial)

`red_team_agent.py` → `RedTeamAgent` is registered.

> **Gap**: AFL++, Boofuzz, and Jazzer fuzzing integration described in BUILD_PLAN Phase 11 not confirmed implemented. Need to check if `red_team_agent.py` actually invokes fuzzers.

---

### Phase 12: Cheap Pre-Checks (Layer 0) ✅ COMPLETE

`prechecks.py` implements `PreCheckAgent`:
- Banned API detection (`eval`, `exec`, `pickle.loads`, `marshal.loads`, `__import__`)
- `patchi_pattern_count()` — count patterns across files
- `patchi_lint_check()` — wraps ruff/eslint
- `patchi_diff_stat()` — before/after line count comparison

> **Gap (LIMIT-11)**: Silent failure when ruff isn't installed.

---

### Phase 13: Governance & Audit (Layer 3) ✅ COMPLETE

`governance.py` implements:
- `patchi_action_log()` — SQLite audit trail in `.patchi/patchi_actions.db`
- `patchi_policy_gate()` — YAML allow/deny policy check with `never_touch` patterns
- `GovernanceAgent` — walks project files to flag never_touch violations

> **Gap (WRONG-06)**: `GovernanceAgent._run()` walks every file on every scan, even when only checking policy violations for patched files.
> **Gap**: `patchi_policy_gate()` is not yet wired into `risk_gate.py` or `applier.py`.

---

### Phase 14: Operational Analytics (Layer 4) ✅ COMPLETE

`history.py` implements:
- `patchi_record_scan()` — records scans to SQLite `patchi_history.db`
- `patchi_verify_finding()` — marks findings as verified
- `patchi_get_history()` / `patchi_get_analytics()` — trend queries
- `HistoryAgent` — returns analytics as `result.data`

> **Gap**: Health score not included in `scan_history` table (MISS-11, CHANGE-09).
> **Gap**: No History panel in the web UI (MISS-08).

---

### New Testing Modules Added

| Module | Description | Status |
|---|---|---|
| `security_test_agent.py` | Per-route security test generation | ✅ Registered |
| `e2e_flow_agent.py` | AI-generated Playwright E2E tests | ✅ Registered |
| `ui_accessibility_agent.py` | Accessibility testing | ✅ Registered |
| `ui_button_agent.py` | Button interaction testing | ✅ Registered |
| `ui_layout_agent.py` | Layout/responsive testing | ✅ Registered |
| `visual_regression_agent.py` | Visual regression testing | ✅ Registered |
| `live_test_runner.py` | Live test execution | ✅ Registered |

> **Gap**: `test_cmd.py` may not expose all these new test agents. Need to verify `p test` subcommands include `security`, `e2e`, `accessibility`, `visual`.

---

### Installation Tooling Added ✅

- `install.sh` — Linux/macOS installer with Python version check, venv, alias setup
- `install.ps1` — Windows PowerShell installer with PATH setup
- `Makefile` — `install`, `install-dev`, `test`, `test-new`, `lint`, `format`, `web`, `scan`, `scan-security`, `clean`

Per `06_VENV_INSTALLATION_PLAN.md` and `07_EHIS_VISION_PLAN.md`.

> **Gap**: Both scripts call `pip install -e ".[dev]"` directly without creating a venv first, unlike the plan's spec which described `python -m venv .venv` as step 1. Users need to create a venv manually.

---

### Learning Brain ✅ COMPLETE

`learning.py` implements:
- `record_acceptance()` / `record_rejection()` with timestamps
- `should_suggest()` — Bayesian classifier with recency decay
- `get_agent_trust()` — per-agent trust score (0–1)
- Exponential decay over 30-day half-life

> **Gap**: `explain_cmd.py` never calls `record_acceptance` or `record_rejection` (MISS-03, UPGRADE-11).

---
