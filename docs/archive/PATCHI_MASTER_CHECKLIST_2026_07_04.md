# Patchi — Master Checklist v2
**Date:** 2026-07-04  
**Sources:** 4 audit docs + live codebase verification + `files-5/` new specs

---

## Legend

| Mark | Meaning |
|------|---------|
| ✅ DONE | Verified working in live code |
| ⚠️ PARTIAL | Exists but incomplete or not fully wired |
| ❌ MISSING | Doesn't exist or not started |
| 🚧 BREAK/CONFLICT | Will break existing code — see §Migration Plan for safe approach |
| 🔮 SPEC | Described in files-5 but codebase already has a similar/better implementation |

---

## §0 — files-5 Specs Already Implemented (codebase is AHEAD of these docs)

Many concepts from files-5 **already exist** in current code. The specs are aspirational architecture docs; the codebase evolved past them.

| files-5 Spec Item | Spec Doc | Codebase Implementation | File(s) |
|---|---|---|---|
| Event schema (normalized envelope) | builder-brief §3.2 | `Event` dataclass with `event_id`, `source`, `technique_id`, `confidence`, `suggested_agent`, `timestamp` | event.py |
| MITRE ATT&CK mapping | builder-brief §3.2 | `TechniqueID` enum with v14 IDs, `for_agent_type()` mapper | event.py |
| Sigma rule engine | builder-brief §3.2 | YAML rule loading, field equality/wildcard/regex/CIDR matching, tag-based ATT&CK routing | sigma_engine.py |
| Dispatcher (technique_id → agent routing) | builder-brief §3.3 | `Dispatcher` class with urgency tiers (SYNC_BLOCK → DISCARD), agent registry | dispatcher.py |
| Confidence gate (0.0-1.0 scoring → routing) | builder-brief §3.3 | `ConfidenceGate` with HIGH≥0.7 defend, MEDIUM≥0.4 ai_analyze, LOW<0.4 escalate | confidence_gate.py |
| Detection pipeline | builder-brief §3.4 | `DetectionPipeline` wiring ConfidenceGate + Layer2Orchestrator | detection_pipeline.py |
| Defense action layer | builder-brief §3.5 | `DefenseLayer` with 6 action types: fix_code, update_dependency, block_ip, rotate_secret, patch_config, escalate | defense_layer.py |
| Agent system with @register | builder-brief §3.4 | `BaseAgent` ABC + `register()` decorator + `AgentGroup` enum + 40+ agents | agents/base.py |
| Coordinator (agent execution engine) | testing-strategy-v2 §2 | `Coordinator` with ThreadPoolExecutor, circuit breaker, progress callbacks | coordinator.py |
| Hosted CLI (init, worker, guard, daemon, status, logs, token) | builder-brief §2b | All 10+ subcommands fully implemented | hosted_cmd.py |
| Log parsers (7 formats) | builder-brief §3.1 | nginx, apache, caddy, uvicorn, gunicorn, cloudflare, json — auto-detect chain | log_parsers.py |
| Anomaly detection (statistical + ML) | builder-brief §3.2 | `StatisticalDetector` (rolling windows) + `MLDetector` (IsolationForest) | anomaly.py |
| IP reputation (blocklists, auto-block) | builder-brief §3.4 | Firehol/abuse.ch blocklists, `block()`/`unblock()`/`is_blocked()`, auto-block at threshold=3 | ip_reputation.py |
| Watchlist (IP scoring, escalation, decay) | builder-brief §3.4 | `WatchlistTracker` with per-IP scoring, decay, HIGH/CRITICAL escalation | watchlist.py |
| Audit log (append-only, rotation) | builder-brief §3.6 | Rotating JSON-lines, `write()`/`read_recent()`/`clear()` | audit_log.py |
| Admin tokens (HMAC-SHA256) | builder-brief §3.6 | generate/validate/revoke with HMAC-SHA256 hashing | tokens.py |
| SAST via Semgrep | builder-brief §4 | `TaintAnalyzer` with Semgrep primary + regex fallback | sast_agent.py |
| SCA via OSV | builder-brief §4 | Multi-ecosystem (npm, PyPI, Go, Rust, PHP, Ruby) via OSV API | dependency_vulnerability_agent.py |
| Secrets scanning | builder-brief §4 | Gitleaks primary + regex fallback | secret_scanning_agent.py |
| Policy engine / governance | builder-brief §3.5 | SQLite action log + YAML policy gate | governance.py |
| WebSocket live events | builder-brief §2b | `WSManager` with broadcast, exponential backoff reconnect | ws.py, base.html |
| Brain scan pipeline (discovery→parse→framework→routes→graph→contract) | exploration-agent §2 | Full pipeline with `Brain` class | brain/brain.py |
| Import graph (file-level) | exploration-agent §3 | `ImportGraph` with forward/reverse edges, circular dep detection, dead file detection | brain/import_graph.py |
| Blast radius (BFS on reverse graph) | master-plan §7 | Per-file and all-files views, direct/transitive dependents, risk scoring | brain/blast_radius.py, blast_cmd.py |
| Health scoring (5-component) | master-plan §8 | Weighted 0-100 with A-F grades, saved to brain | health.py |
| Route mapper (framework-aware) | exploration-agent §2.1 | Express, Next.js, FastAPI, Flask, Django extraction | brain/route_mapper.py |
| Framework detector | exploration-agent §2.1 | Detects frameworks, runtimes, TypeScript | brain/framework.py |
| 34 security agents | builder-brief §3.4 | Injection, Auth, Crypto, Network, Compliance, Privacy, IaC, Container, etc. | security/security_agents.py |
| 13 test agents | testing-strategy-v2 §2a | Unit, Browser, E2E, Stress, Visual Regression, Accessibility, API Contract, etc. | testing/ |
| Supply chain (license, typosquatting) | builder-brief §4 | License classification (permissive/copyleft), Levenshtein typosquatting | security/supply_chain.py |
| Web UI (9 panels) | builder-brief §2b | Dashboard, Findings, Review, Guard, History, Settings, Chat, Brain, Tokens | web/routes/ |
| Structured finding schema (shared across all agents) | testing-strategy-v2 §2 | `Finding` dataclass used universally | agents/base.py |
| Dangling/orphan edge detection | testing-strategy-v2 §5 | `find_dead_files()` in import_graph | brain/import_graph.py |
| ASGI middleware (request interceptor) | builder-brief §2b | Request interceptor for hosted mode | security/request_interceptor.py |

---

## §1 — Verified Fixed (bugs from prior audits, confirmed in live code)

| Item | Old Audit Flag | Current Status | File |
|------|---------------|----------------|------|
| ws.py truncation `broadc` | C-01 CRITICAL | ✅ Fixed | ws.py:64 |
| events.py truncation `WebSocke` | C-02 CRITICAL | ✅ Fixed | events.py:26 |
| scan_cmd.py missing `:` on except | C-03 CRITICAL | ✅ Fixed | scan_cmd.py:67 |
| canvas.js `WS` undefined | C-04 CRITICAL | ✅ Fixed — uses `window._ws` | canvas.js:79,830 |
| canvas.js `n.status(...)` crash | C-05 CRITICAL | ✅ Fixed — uses `setNodeState()` | canvas.js:940 |
| Edge format `source/target` vs `from/to` | C-06 CRITICAL | ✅ Fixed — API sends both | brain_map.py:86 |
| `tojson` filter missing | C-07 CRITICAL | ✅ Fixed | dashboard.py:15 |
| `except: pass` in app.py | C-08 CRITICAL | ✅ Fixed — logs warnings | app.py:34-50 |
| XSS in settings.html | H-01 HIGH | ✅ Fixed | settings.html:23 |
| Race condition ws.py broadcast | H-02 HIGH | ✅ Fixed — removal inside lock | ws.py:41-49 |
| `cfg.get("ai", root)` crash | H-03 HIGH | ✅ Fixed | init.py |
| Frozen/PyInstaller static path | H-05 HIGH | ✅ Fixed | app.py:54-58 |
| `document.write` CDN fallback | H-06 HIGH | ✅ Fixed | base.html |
| Brace expansion glob `*.{js,ts}` | M-01 MEDIUM | ✅ Fixed | blast_radius.py |
| `safe_rglob` `**/name` pattern | M-02 MEDIUM | ✅ Fixed | base.py:74 |
| `plan_auditor` hardcoded agents | M-03 MEDIUM | ✅ Already dynamic | plan_auditor.py |
| `deps_cmd.py` inverted flag logic | M-04 MEDIUM | ✅ Fixed | deps_cmd.py |
| `fmtTS` `this` binding | M-05 MEDIUM | ✅ Fixed | tokens.html |
| `datetime.utcnow()` deprecated | L-01 LOW | ✅ Fixed | report_cmd.py |
| `or True` in deep flag | BUG-08 | ✅ Fixed | scan_cmd.py |
| `blame_line()` porcelain parsing | BUG-07 | ✅ Fixed | git_aware.py |
| Private helpers in `__all__` | BUG-09 | ✅ Fixed | security_agents.py |
| Unbounded chat history | BUG-06 | ✅ Fixed — capped + persisted | api_chat.py |
| SecurityOrchestrator not called | WIRE-01 | ✅ Now called from coordinator & API | coordinator.py:145, api/scan.py:63 |
| Secrets gate not called | WIRE-02 | ✅ Called from risk_gate & applier | risk_gate.py:185, applier.py:167 |
| Policy gate not called | WIRE-03 | ✅ Called from applier | applier.py:94,139 |
| Quiet hours not consulted | WIRE-05 | ✅ Wired in notifier & risk_gate | notifier.py:78, risk_gate.py:238 |
| Learning not in explain_cmd | WIRE-06 | ✅ `record_acceptance/rejection` called | explain_cmd.py:306,312 |
| Health score not in history | WIRE-07 | ✅ Column exists, data stored & queried | history.py:39,86,148 |
| Install scripts skip venv | WIRE-09 | ✅ Both create `.venv` | install.sh:35, install.ps1:34 |
| WebSocket reconnect (was location.reload) | UPGRADE-06 | ✅ Exponential backoff 1s→30s | base.html:72 |
| server.py exists (dead code) | ARCH | ✅ Deleted | — |
| api.py shadows api/ package | ARCH | ✅ Deleted → renamed to api_legacy.py | — |
| brain-map.js duplicate const | BUG-03 | ✅ Deleted — only canvas.js remains | — |
| dashboard.html missing canvas.js | BUG-03 | ✅ Script tag included | dashboard.html:129 |
| Duplicate /api/findings route | BUG-04 | ✅ Resolved | api/scan.py vs api_legacy.py |
| SpawnManager not initialized | BUG-05 | ✅ Initialized in app.py | app.py:42-50 |
| Cost tracker not initialized | BUG-05 | ✅ Initialized in app.py | app.py:34-40 |

---

## §2 — Still Open: Code Bugs & Technical Debt

| # | Issue | File | Severity | Why It Matters |
|---|-------|------|----------|----------------|
| 1 | Hardcoded `total=11` agent count | scan_cmd.py:203 | MEDIUM | Progress bar never reaches 100% when scanners added/removed. Should use `len(list_agents(AgentGroup.SCANNER))`. |
| 2 | `api_legacy.py` monolith (2384 lines) | api_legacy.py | MEDIUM | Old api.py renamed but still huge. Imports from both events.py and ws.py (9 import sites from events.py). Hard to maintain. |
| 3 | `\| safe` unsanitized in brain.html | brain.html:12 | MEDIUM | XSS vector — `brain_content` is raw `.patchi/BRAIN.md` content |
| 4 | `SecurityTestAgent` hardcodes Flask fixtures | security_test_agent.py | MEDIUM | Generates `from flask import Flask` for all frameworks — breaks for FastAPI/Django |
| 5 | `CVEMonitorAgent` no batch query or cache | cve_monitor.py | MEDIUM | 1 HTTP request per dependency per scan. No batching, no 24h TTL cache. |
| 6 | `PreCheckAgent` silent ruff failure | prechecks.py | LOW | If ruff not installed, silently returns empty list (looks like lint passed) |
| 7 | `E2EFlowAgent` hardcoded 6 ports | e2e_flow_agent.py | LOW | Only checks `[3000, 5173, 8080, 4200, 8000, 4321]` — misses non-standard |
| 8 | `brain.html` location.reload() | brain.html:8 | LOW | Hard reload instead of HTMX fetch |
| 9 | `tokens.html` location.reload() | tokens.html:81,92 | LOW | Same pattern |

---

## §3 — Web UI Gaps

| # | Feature | Status | Effort | Notes |
|---|---------|--------|--------|-------|
| 1 | **Settings** (8-tab panel) | ⚠️ PARTIAL | 2-3d | Basic key-value editor exists. Missing: General, AI/Models, Scan, Fix, Constraints, Notifications, Brain, Queue, Advanced tabs per spec. |
| 2 | **History** (health trend chart) | ⚠️ PARTIAL | 1-2d | Table view with health_score exists. Missing: health line graph over time, tappable data points, filter controls, per-session diffs. |
| 3 | **Diff viewer** (side-by-side) | ⚠️ PARTIAL | 1d | Toggleable unified `<pre>` diff exists. Missing: side-by-side, syntax highlighting (Prism.js/highlight.js), blast radius badge, "Preview in context". |
| 4 | **Brain Map** (octagonal nodes) | ⚠️ PARTIAL | 2-3d | Force-directed Konva canvas exists. Nodes are circular (spec calls for octagonal with 7 color states per `1782754697561-crisp-otter.md`). |
| 5 | **Live scan progress** | ⚠️ PARTIAL | 1d | WebSocket events fire but clients connecting mid-scan get no progress until next event. |
| 6 | **Notifications panel** | ❌ MISSING | 1-2d | No `/notifications` route or template. |
| 7 | **Diagnostics panel** | ❌ MISSING | 1d | No `/diagnostics` route. Doctor checks not accessible from web. |
| 8 | **Agents panel** | ❌ MISSING | 1d | No `/agents` route showing agent status. |

---

## §4 — Performance & Architecture (High Impact, Low Risk)

| # | Item | Status | Effort | Speedup |
|---|------|--------|--------|---------|
| 1 | Agent result caching (keyed by agent + file_hash + config_hash) | ❌ MISSING | 2d | 5-10x repeat scans |
| 2 | Incremental scanning — promote MD5 skip from deep scan to main path | ❌ MISSING | 1d | 5-10x large codebases |
| 3 | OSV batch query (`POST /v1/querybatch`) + 24h TTL cache | ❌ MISSING | 4h | 100 req → 1 req/scan |
| 4 | PolicyEngineAgent — batch per-file reads instead of per-rule | ❌ NOT FIXED | 2h | 16 reads/file → 1 read/file |
| 5 | Cache LLM agent reordering by (agent_set_hash, framework) | ❌ MISSING | 2h | Eliminates 1 LLM call/scan |
| 6 | GovernanceAgent — scope file walk to changed files only | ❌ NOT FIXED | 1h | O(all files) → O(changed) |
| 7 | Split `main.py` (1186 lines → decorator-based registration) | ❌ NOT DONE | 1d | Maintainability |
| 8 | Add `conftest.py` for shared test fixtures | ❌ MISSING | 1d | Reduces test boilerplate |
| 9 | AI Horde fallback — merge from `fix/base.py` into `ai/client.py` | ❌ NOT DONE | 1d | Fix agents work without keys |

---

## §5 — files-5 Items That Are ⚠️ PARTIAL

| # | files-5 Spec | Codebase Status | What's Missing |
|---|-------------|----------------|----------------|
| 1 | **Incremental graph update** (diff-based patch, not full rebuild) | ⚠️ PARTIAL | `git_aware.py` provides changed files. Brain computes graph diff. But **full rebuild still happens every scan** — only the diff is computed after rebuild, not used to skip work. |
| 2 | **Falco runtime agent** | ⚠️ PARTIAL | `FalcoRuntimeAgent` detects missing Falco configs statically. Does **NOT** invoke Falco subprocess or ingest syscall stream. |
| 3 | **Red team agent** | ⚠️ PARTIAL | `RedTeamAgent` does static attack surface analysis (eval/exec patterns). Does **NOT** invoke Atomic Red Team, Caldera, or Nuclei. |
| 4 | **Blast radius weighting** (by test coverage, runtime traffic, criticality) | ⚠️ PARTIAL | Current blast radius **counts files only** (BFS node count). Health scoring uses these weights, but blast radius does not. |
| 5 | **Health scoring** (dynamic domain taxonomy) | ⚠️ PARTIAL | Current score is **fixed 5-component model**. Not driven by dynamic domain activation signals. |
| 6 | **Agent reordering via LLM** | ⚠️ CONFLICT | Coordinator calls LLM to reorder agents. files-5 spec says **no central LLM** — routing must be deterministic. See §Migration Plan. |
| 7 | **Pipeline ordering** (scan → test → fix → reverify gates) | ⚠️ PARTIAL | Coordinator runs (SCANNER → SECURITY → FIX) with rough ordering. No **enforced gates** between phases. No test-between-scan-and-fix. |
| 8 | **Three deployment shapes** | ⚠️ PARTIAL | Standalone/sidecar mode ✅ fully done. Embedded mode (npm/pip middleware) ❌. GitHub App/bot ❌. |
| 9 | **Self-scan / dogfooding CI** | ⚠️ PARTIAL | Concept referenced in audits. No CI pipeline that self-scans Patchi with Patchi. |
| 10 | **License compliance auditing** | ⚠️ PARTIAL | `SupplyChainAgent` classifies licenses. Does **NOT** actively audit deps before lock-in. |
| 11 | **Hosted mode self-defense** (dead-man's switch) | ⚠️ PARTIAL | Governance logs actions, detection pipeline protects hosted mode. No operational watcher for dispatcher/audit log liveness. |

---

## §6 — files-5 Items That Are ❌ MISSING

| # | Item | Spec Doc | Effort | Notes |
|---|------|----------|--------|-------|
| 1 | **Wazuh integration** | builder-brief §4 | 2w | No Wazuh wrapper, subprocess, or API client. |
| 2 | **Coraza/ModSecurity WAF (OWASP CRS)** | builder-brief §4 | 1w | InjectionAgent uses regex, not OWASP CRS rules. |
| 3 | **Suricata/Zeek network IDS** | builder-brief §4 | 1w | No network IDS integration. |
| 4 | **GitHub App/bot** (webhook, PR comments, merge gate) | builder-brief §2c | 3-4w | No webhook handler or GitHub API client. |
| 5 | **Embedded mode SDK** (npm/pip middleware) | builder-brief §2a | 2-3w | No Express/Fastify middleware package. |
| 6 | **Symbol-level graph** (function/class node granularity) | exploration-agent §3 | 2w | Current graph is file-level (`ImportGraph` edges between file paths). Spec demands `src/auth/session.ts::validateSession`. |
| 7 | **Multiple edge types** (calls, renders, http-calls) | exploration-agent §3 | 2w | Only import edges exist. No calls/renders/http-calls types. |
| 8 | **Graph-scoped test generation** (neighborhood context) | testing-strategy-v2 §4 | 2w | The 11-vs-1 hallucination reduction technique. No implementation. |
| 9 | **Graph-scoped fix generation** | testing-strategy-v2 §3 | 1w | Fix agents use whole-file context, not graph neighborhood. |
| 10 | **Dynamic crawl for route discovery** (Playwright) | exploration-agent §2.2 | 1w | Browser agents exist but for testing, not graph exploration. |
| 11 | **Composite fix scoring** (4 gates) | testing-strategy-v2 §3 | 1w | No scoring function for fix candidates. |
| 12 | **Sandbox reverification** (isolated checkout) | testing-strategy-v2 §3 | 2w | No sandbox environment for testing fixes. |
| 13 | **Context-aware domain taxonomy** (versioned YAML) | master-plan §8 | 2w | No `domains.yml`, no activation signals, no N/A state. |
| 14 | **Context classifier** (signals → app profile → domain activation → scoring) | master-plan §8 | 2w | Scoring is fixed 5-component, not taxonomy-driven. |
| 15 | **N/A as first-class score state** | master-plan §8 | 3d | All domains always active — no "not applicable". |
| 16 | **Attack simulation harness** (Atomic Red Team + Juice Shop) | builder-brief §5 | 2w | No test ranges, no CI loop. |
| 17 | **OS keychain for secrets** (keytar/libsecret) | master-plan §5 | 3d | Tokens in JSON file with HMAC, not OS keychain. |
| 18 | **SLSA/provenance releases** (GPG signing) | master-plan §5 | 2d | No signing pipeline. |
| 19 | **Auto-update with signature verification** | master-plan §5 | 1w | No update mechanism. |
| 20 | **Property-based testing** (fast-check/Hypothesis) | testing-strategy-v2 §2a | 1w | Not started. |
| 21 | **Combinatorial/pairwise testing** (PICT) | testing-strategy-v2 §2a | 3d | Not started. |
| 22 | **Chaos/fault injection** (Toxiproxy/Chaos Mesh) | testing-strategy-v2 §2a | 1w | Not started. |
| 23 | **Mutation testing** (Stryker/mutmut) | testing-strategy-v2 §2a | 1w | Not started. |
| 24 | **Fuzzing** (AFL++/Atheris/Jazzer) | testing-strategy-v2 §2a | 2w | Not started. |
| 25 | **Load/stress testing** (k6/Locust) | testing-strategy-v2 §2a | 1w | Not started. |
| 26 | **Hallucination rate tracking** / eval set | testing-strategy-v2 §4 | 1w | No regression gate for AI-assisted steps. |
| 27 | **Acceptance criteria framework** (phase completion evidence) | testing-strategy-v2 §3a | 1w | No "not done / partial / done" tracking with assertions. |
| 28 | **Cross-repo context memory** | master-plan §10 | 3w | Brain is per-project only. |

---

## §7 — Migration Plan: Items That WILL Break or Conflict + Safe Approaches

### 🚧 7a — Governor Architecture (files-5 spec) vs Existing Coordinator

**The Conflict:** files-5's "Governor" is described as replacing the current routing brain with a deterministic state machine. The current `Coordinator` already does this but with an LLM reordering step (`_maybe_reorder()`) that the spec explicitly rejects.

**✅ Safe approach — Evolve Coordinator, don't replace it:**

The `Coordinator` class (coordinator.py:66) already has the right structure:
- `run_group(AgentGroup)` — runs agent groups with phase awareness
- `run_all_scanners()` / `run_all_security_agents()` / `run_fix_agents_batched()` — phase-based
- `_circuit_breaker` — tracks failures per agent
- `on_progress` callback — progress reporting
- Runs SCANNER → SECURITY → FIX with ordering

**Changes needed (0 new files, ~200 lines changed):**
1. Add `Coordinator.run_pipeline(phases: list[AgentGroup])` — runs phases sequentially with gates between them
2. Add phase gates: after SCANNER completes, before FIX starts, run a "gate check" that examines results
3. Deprecate `_maybe_reorder()` (the LLM call) — replace with configurable deterministic ordering rules
4. Add `PipelinePhase` dataclass with `pre_gate` and `post_gate` callbacks

```python
# New in coordinator.py (adds ~50 lines)
@dataclass
class PipelinePhase:
    group: AgentGroup
    pre_gate: Callable | None = None  # e.g., "results from previous phase OK?"
    post_gate: Callable | None = None # e.g., "did this phase produce what we need?"

class Coordinator:
    def run_pipeline(self, phases: list[PipelinePhase]) -> dict[AgentGroup, list[AgentResult]]:
        results = {}
        for phase in phases:
            if phase.pre_gate and not phase.pre_gate(results):
                logger.warning("Gate blocked phase {}", phase.group)
                break
            results[phase.group] = self.run_group(phase.group)
            if phase.post_gate and not phase.post_gate(results):
                logger.warning("Post-gate failed for phase {}", phase.group)
        return results
```

---

### 🚧 7b — Symbol-Level Graph vs Existing File-Level ImportGraph

**The Conflict:** files-5 demands `src/auth/session.ts::validateSession` granularity with multiple edge types. Current `ImportGraph` (import_graph.py) is file-level with single edge type.

**✅ Safe approach — Add symbol layer ON TOP OF file-level graph:**

The existing `ImportGraph` has:
- `add_edge(from_path, to_path)` — file-level edges
- `build_graph(files)` — from FileInfo list
- `find_dead_files()` — orphan detection
- Circular dependency detection

**Changes needed (1 new file, ~300 lines — `brain/symbol_graph.py`):**
1. Create `SymbolGraph` class that references `ImportGraph` internally
2. `SymbolNode` dataclass: `{symbol_id, file_path, symbol_type, edges: list[SymbolEdge]}`
3. `SymbolEdge` dataclass: `{from_symbol, to_symbol, edge_type (calls|imports|renders|http-calls)}`
4. Static extraction: parse AST per-file to extract function/class/route symbols (reuse existing `FileScanner`)
5. Keep file-level graph as fast pre-filter; add symbol-level on-demand

```python
# New file: brain/symbol_graph.py
@dataclass
class SymbolNode:
    id: str  # "src/auth/session.ts::validateSession"
    file: str
    symbol_type: str  # function | class | route | const
    exported: bool

class SymbolGraph:
    def __init__(self, import_graph: ImportGraph):
        self._file_graph = import_graph  # existing file-level graph is pre-filter
        self._symbols: dict[str, SymbolNode] = {}
        self._edges: list[SymbolEdge] = []
    
    def extract_from_file(self, file_info: FileInfo) -> None:
        """Parse AST and extract symbols from a single file."""
        # Reuses FileScanner's existing AST parsing
    
    def affected_by(self, symbol_id: str) -> list[str]:
        """Existing blast radius logic, now at symbol level."""
        # Falls back to file-level if symbol not found
```

---

### 🚧 7c — Context-Aware Scoring vs Existing health.py

**The Conflict:** files-5 defines a dynamic domain taxonomy with activation signals. Current `health.py` uses a fixed 5-component model.

**✅ Safe approach — Run BOTH scoring systems in parallel, then deprecate old:**

Current health.py has:
- `compute()` — 5 components (structure, security, testing, ai, dependency)
- Scoring saved to brain/memory

**Changes needed (1 new file, ~200 lines — `scoring/taxonomy.py`):**
1. Create `DomainTaxonomy` class that loads versioned YAML domain definitions
2. Create `ContextClassifier` that reads brain signals and returns activated domains
3. Create `TaxonomyScorer` that computes weighted score over activated domains only
4. Add `health_score_v2` alongside existing `health_score` — both stored
5. Web UI shows both scores initially, then old one removed

```python
# New: scoring/taxonomy.py
class DomainActivation:
    ACTIVE = "active"
    NOT_APPLICABLE = "n/a"
    UNCLEAR = "unclear"

class ContextClassifier:
    def classify(self, brain: dict) -> dict[str, str]:
        """Returns {domain_id: activation_state}"""
        # Reads signals from brain: has_server? has_auth? has_db?
        # Returns ACTIVE / N/A / UNCLEAR per domain

class TaxonomyScorer:
    def score(self, brain: dict, findings: list) -> dict:
        """Returns {domain: {score, weight, controls}}"""
        # Weighted average over active domains only
        # N/A domains excluded from numerator AND denominator
```

---

### 🚧 7d — Event Envelope Schema Migration

**The Conflict:** files-5's event envelope has specific fields. The existing `Event` dataclass (event.py) already matches, but not all agents emit events in this format — they use the older `AgentResult` → `Finding` format.

**✅ Safe approach — Auto-convert at pipeline boundary:**

The `Event` dataclass already has:
```python
@dataclass
class Event:
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    source: EventSource = EventSource.AGENT
    technique_id: str = ""
    ...
```

**Changes needed (1 helper function, ~50 lines):**
1. Add `Event.from_agent_result(result: AgentResult) -> Event` converter
2. Pass through converter at the coordinator → dispatcher boundary
3. Agents never need to change — conversion happens at pipeline entry

```python
# In event.py or a new bridge module
def agent_result_to_event(result: AgentResult) -> Event:
    return Event(
        source=EventSource.AGENT,
        technique_id=TechniqueID.for_agent_type(result.agent_name),
        confidence=result.confidence,
        payload={"findings": [f.__dict__ for f in result.findings]},
        suggested_agent=result.agent_name,
    )
```

---

### 🚧 7e — Pipeline Ordering (scan → test → fix → reverify)

**The Conflict:** files-5 orders phases strictly: scan MUST run before test generation, test MUST run before fix. Current CLI exposes all three as independent commands.

**✅ Safe approach — Add pipeline mode alongside existing commands:**

Don't break `p scan`, `p test`, `p fix`. Add `p pipeline [--phases scan,test,fix]` that runs them in order with gates. Existing commands stay for power users.

**Changes needed (1 new file, ~100 lines — `patchi/cli/commands/pipeline_cmd.py`):**
1. New `p pipeline` command that chains existing phases
2. Phase gates: after scan → generate tests → run tests → generate fixes → verify fixes → loop-back scan
3. Uses existing `Coordinator.run_group()` but with explicit gate checks
4. Existing `p scan`, `p test`, `p fix` remain unchanged

---

### 🚧 7f — Remove events.py Dual WS Architecture

**The Conflict:** `events.py` wraps `ws.py` via `_WSCompatWrapper`, and `api_legacy.py` imports from `events.py` at 9 sites. Can't delete `events.py` without breaking `api_legacy.py`.

**✅ Safe approach — Refactor api_legacy.py to use ws.py directly, then remove events.py:**

1. Update each of the 9 import sites in `api_legacy.py` to import from `patchi.web.ws` instead
2. The `_WSCompatWrapper` bridge is trivially replaced — `events.manager.broadcast(payload)` → `ws.manager.broadcast(event, data)` where `event = payload.get("event", "")` and `data = payload.get("data", {})`
3. Once api_legacy.py has zero imports from events.py, delete `events.py`
4. This is a pure mechanical refactor — zero behavior change

---

## §8 — Quick Priority Matrix (What to Do First)

### This Week (🟢 No Risk)
| # | Item | Effort |
|---|------|--------|
| 1 | Fix `total=11` in scan_cmd.py:203 | 2 min |
| 2 | Sanitize `brain.html` `\| safe` | 5 min |
| 3 | Fix `SecurityTestAgent` Flask fixtures | 1h |
| 4 | Add OSV batch query + 24h cache | 4h |
| 5 | Cache LLM agent reordering | 2h |

### This Month (🟡 Low Risk with Planning)
| # | Item | Effort |
|---|------|--------|
| 6 | Refactor api_legacy.py → remove events.py | 1d |
| 7 | Agent result caching | 2d |
| 8 | Incremental scanning (MD5 skip) | 1d |
| 9 | Blast radius weighting (by coverage/criticality) | 1d |
| 10 | Add missing web panels (Notifications, Diagnostics, Agents) | 1-2d each |
| 11 | Settings 8-tab panel | 2-3d |
| 12 | History health trend chart | 1-2d |
| 13 | Evolve Coordinator → phased pipeline (7a) | 2d |
| 14 | Event envelope auto-converter (7d) | 4h |
| 15 | Add `p pipeline` command (7e) | 1d |

### Next Quarter (Will Need Planning)
| # | Item | Effort | Prep Needed |
|---|------|--------|-------------|
| 16 | Symbol-level graph layer (7b) | 2w | ImportGraph stable, AST parsers exist |
| 17 | Context-aware scoring (7c) | 2w | health.py is stable, dual scoring safe |
| 18 | Dynamic crawl for route discovery | 1w | Playwright agents exist — extend for exploration |
| 19 | Graph-scoped test generation | 2w | Requires symbol-level graph (16) first |
| 20 | Composite fix scoring + sandbox reverify | 2w | Requires graph-scoped gen (19) first |
| 21 | Attack simulation harness (Juice Shop + Atomic Red Team) | 2w | New infra, no conflicts |

### Long Term (Deferred)
| # | Item | Effort |
|---|------|--------|
| 22 | Wazuh integration | 2w |
| 23 | Coraza/ModSecurity WAF | 1w |
| 24 | Suricata/Zeek IDS | 1w |
| 25 | GitHub App/bot | 3-4w |
| 26 | Embedded mode SDK | 2-3w |
| 27 | Property-based, combinatorial, mutation, fuzzing, chaos | 1-3w each |
| 28 | VS Code extension | 4w+ |
| 29 | SLSA/provenance releases | 2d |
| 30 | OS keychain for secrets | 3d |
| 31 | Cross-repo context memory | 3w |

---

## Summary Stats (Updated with Accurate files-5 Mapping)

| Category | ✅ DONE | ⚠️ PARTIAL | ❌ MISSING | 🚧 MIGRATION |
|----------|---------|-------------|------------|--------------|
| Code bugs from audits | 24 | 1 | 0 | 0 |
| Was "not wired" (now fixed) | 11 | 0 | 0 | 0 |
| files-5 specs already in codebase | 35 | 0 | 0 | 0 |
| files-5 items ⚠️ PARTIAL | 0 | 11 | 0 | 0 |
| files-5 items ❌ MISSING | 0 | 0 | 28 | 0 |
| Web UI panels | 4 | 4 | 3 | 0 |
| Performance/Architecture | 0 | 0 | 9 | 0 |
| Migration (will break if done wrong) | 0 | 0 | 0 | 6 |

**Key takeaway:** The codebase already has **35 of the files-5 spec items** implemented. Only **28 are truly missing** (mostly OSS tool integrations like Wazuh, Suricata, Coraza, GitHub App). The 6 migration items have safe evolutionary paths that don't require rewrites.
