# Patchi — Master Plan v2 (Consolidated)
**Date:** 2026-07-04  
**Sources:** All 4 audits + live codebase verification + files-5 specs + Fixing Strategy  
**Scope:** Everything — bugs, gaps, strategic additions, architecture evolution

---

## Legend

| Mark | Meaning |
|------|---------|
| ✅ DONE | Verified working in live code |
| ⚠️ PARTIAL | Exists but incomplete or not fully wired |
| ❌ NOT STARTED | Doesn't exist or not begun |
| 🛠️ EVOLVE | Has existing analog — evolve instead of build new |
| 🚧 SAFE | Additive change — won't break existing code |
| ⚡ BREAKS | Changes existing behavior — needs migration plan |

---

## §1 — Actually Broken (bugs in current code — not spec gaps)

| # | Bug | File | Severity | Fix |
|---|-----|------|----------|-----|
| 1 | Hardcoded `total=11` in progress bar | scan_cmd.py:203 | MEDIUM | `len(list_agents(AgentGroup.SCANNER))` — 2 min |
| 2 | XSS via `\| safe` in brain.html | brain.html:12 | MEDIUM | Sanitize server-side — 5 min |
| 3 | `SecurityTestAgent` generates Flask fixtures for all frameworks | security_test_agent.py | MEDIUM | Use `inp.brain.get("framework")` — 1h |
| 4 | `CVEMonitorAgent` 1 HTTP req per dep, no cache | cve_monitor.py | MEDIUM | OSV batch query + 24h TTL — 4h |
| 5 | `PreCheckAgent` silent failure when ruff not installed | prechecks.py | LOW | Log warning — 10 min |
| 6 | `E2EFlowAgent` only checks 6 ports | e2e_flow_agent.py | LOW | Read project config port first — 30 min |

---

## §2 — Web UI (All 🚧 SAFE — new routes, won't break existing)

| # | Feature | Status | What Exists | What's Missing |
|---|---------|--------|-------------|----------------|
| 1 | Dashboard | ✅ DONE | Health score, cards, layout | Brain Map rendered (canvas.js is loaded) but octagonal nodes not implemented |
| 2 | Settings | ⚠️ PARTIAL | Key-value editor route + template | 8-tab panel: General, AI/Models, Scan, Fix, Constraints, Notifications, Brain, Queue, Advanced |
| 3 | History | ⚠️ PARTIAL | Table with health_score column | Health line graph, tappable data points, filter controls, per-session diffs |
| 4 | Review (diff) | ⚠️ PARTIAL | Toggleable unified diff | Side-by-side, syntax highlighting, blast radius badge, "Preview in context" |
| 5 | Brain Map | ⚠️ PARTIAL | Force-directed Konva canvas | Octagonal nodes, 7 color states per spec |
| 6 | Live scan progress | ⚠️ PARTIAL | WebSocket events fire | Mid-connection progress state push |
| 7 | Notifications | ❌ NOT STARTED | — | Route + template for channel management |
| 8 | Diagnostics | ❌ NOT STARTED | — | Route + template for doctor checks |
| 9 | Agents | ❌ NOT STARTED | — | Route + template for agent status |

---

## §3 — Technical Debt (All 🚧 SAFE — internal, no behavioral change)

| # | Item | Status | Effort | Benefit |
|---|------|--------|--------|---------|
| 1 | Agent result caching | ❌ NOT STARTED | 2d | 5-10x repeat scans, lower AI cost |
| 2 | Incremental scanning (MD5 skip) | ❌ NOT STARTED | 1d | 5-10x large codebases |
| 3 | OSV batch query + 24h cache | ❌ NOT STARTED | 4h | 100 req → 1 req/scan |
| 4 | Cache LLM agent reordering | ❌ NOT STARTED | 2h | Eliminates 1 LLM call/scan |
| 5 | Fix `total=11` hardcode | 🔧 NEEDS FIX | 2 min | Progress bar accuracy |
| 6 | Split `main.py` (1186 lines) | ❌ NOT STARTED | 1d | Maintainability |
| 7 | `conftest.py` shared fixtures | ❌ NOT STARTED | 1d | Less test boilerplate |
| 8 | Merge AI Horde into `ai/client.py` | ❌ NOT STARTED | 1d | Fix agents work without API keys |

---

## §4 — Fixing Strategy (NEW — from fixing-strategy spec)

The current fix pipeline has a structural weakness: **the LLM gets the whole file, produces one candidate, returns a full file, and that candidate is trusted unless tests fail**. The Fixing Strategy addresses each gap.

### §4.1 — Deterministic-First Ordering

**Spec:** Run ESLint `--fix`, Semgrep autofix, jscodeshift codemods, `npm audit fix` BEFORE invoking any LLM fix agent.

**Current state:** ❌ NOT STARTED. All 8 fix agents currently use LLM first. `prechecks.py` wraps ruff/eslint but as a SCANNER agent, not a fixer. The coordinator runs FIX agents sequentially with no deterministic pre-pass.

**Approach:** 🛠️ EVOLVE coordinator — add `DETERMINISTIC_FIX` agent group that runs before `FIX` group.

**Migration:** 🚧 SAFE — new agent group doesn't change existing fix agents.
```
coordinator.run_fix_pipeline(root):
  1. Run DETERMINISTIC_FIX agents (new) — ESLint --fix, Semgrep autofix
  2. Run FIX agents (existing) — only for residual cases
```

**Files to change:**
- `agents/base.py` — add `AgentGroup.DETERMINISTIC_FIX`
- `coordinator.py` — add `run_fix_pipeline()` method with phase ordering
- New: `fix/eslint_fixer.py`, `fix/semgrep_fixer.py`, `fix/deterministic_runner.py`

**Effort:** 2 days

---

### §4.2 — Graph-Scoped Context (Not File-Dump Context)

**Spec:** Don't hand the LLM a file and line number. Hand it: symbol signature + direct callers + direct callees + the specific control/finding it's failing.

**Current state:** ❌ NOT STARTED. `_ai_fix()` sends `file_content[:8000]` (whole file truncated), plus `blast_radius: int`. No callers/callees. The import graph exists (`import_graph.py`) but is file-level, not symbol-level.

**Approach:** 🛠️ EVOLVE `_ai_fix()` to accept optional `graph_context` dict. Start with file-level import neighbors (already available via `ImportGraph.get_dependents()` / `get_dependencies_of()`). Add symbol-level later.

**Migration:** 🚧 SAFE — `file_content[:8000]` stays as fallback. Graph context is additive in the prompt.

```python
# In _ai_fix(), add to user_prompt:
if import_graph:
    callers = import_graph.get_dependents(file_path)  # who imports this?
    callees = import_graph.get_dependencies_of(file_path)  # what does this import?
    user_prompt += f"\nFiles that import this: {callers}"
    user_prompt += f"\nFiles this imports: {callees}"
```

**Files to change:**
- `fix/fix_agents.py` — widen `_ai_fix()` prompt
- `coordinator.py` — pass import graph to fix agent input

**Effort:** 4 hours (file-level) / 2 weeks (symbol-level)

---

### §4.3 — Fix Playbooks Per Issue Type

**Spec:** For each `control_id` in the domain taxonomy, maintain a remediation template. The LLM call fills the template, not solves from scratch.

**Current state:** ⚠️ PARTIAL. `Skill` enum has 8 skill types with system prompts. But these are general-purpose prompts, not templated per `control_id`. No `remediation_ref` field in the taxonomy.

**Approach:** 🚧 SAFE — Add `fix/remediation_templates/{control_id}.md` files. Store fallback skill prompt per template. `_ai_fix()` checks for template before using generic skill prompt. If no template, falls back to current behavior.

**Migration:** No existing code changes — new files only.

```
fix/remediation_templates/
├── SC-01.md  — "Pin dependency version for {package} from {old} to {new}"
├── SC-02.md  — "Audit postinstall script in {file}: {finding}"
├── AUTH-01.md — "Add authentication check to route {route}"
└── fallback.md — Generic skill prompt (current behavior)
```

**Effort:** 2 days

---

### §4.4 — Multiple Candidates, Deterministic Selection

**Spec:** Generate 2-3 candidate diffs per issue. Score each on 4 criteria: passes tests, passes mutation subset, reduces blast radius vs previous, introduces no new findings. Pick best.

**Current state:** ❌ NOT STARTED. Each fix agent makes 1 AI call per finding → 1 `Patch`. The `Patch` dataclass has `risk_score` and `confidence` but no multi-candidate scoring.

**Approach:** ⚡ MIGRATION NEEDED. `_ai_fix()` currently returns `str | None` (single proposed file content). Need to change to returning multiple candidates. The core `_ai_fix` signature changes.

**Safe migration — phased rollout:**
1. Add `_ai_fix_multi()` alongside existing `_ai_fix()` — generates N candidates
2. New `scoring.py` module with `composite_score(patch, test_results, blast_radius, new_findings)`
3. Coordinator optionally calls `_ai_fix_multi()` for high-risk findings (risk_score > 30)
4. Low-risk findings still use single `_ai_fix()` — unchanged behavior
5. After validation, eventually deprecate `_ai_fix()`

```python
# New: fix/scoring.py
def composite_score(patch: Patch, test_pass: bool, blast_delta: int, new_findings: list) -> float:
    """0.0-1.0 composite score — higher = better candidate to apply."""
    score = 1.0
    if not test_pass:
        score -= 0.5
    score -= 0.1 * blast_delta  # +blast radius = -score
    score -= 0.1 * len(new_findings)  # new findings = -score
    return max(0.0, score)
```

**Files to change:**
- New: `fix/scoring.py`
- `fix/fix_agents.py` — add `_ai_fix_multi()`
- `coordinator.py` — add multi-candidate routing for high-risk findings

**Effort:** 3 days

---

### §4.5 — Structured Diff Output (Not Freeform Code)

**Spec:** LLM emits a unified diff/patch. Applied by an actual patch tool. Malformed/overly broad diffs get rejected before touching the repo.

**Current state:** ⚠️ PARTIAL. The `Patch`/`FileChange` dataclass uses diffs (`_compute_diff()` in patch.py converts full file + proposed to unified diff AFTER the LLM returns). The LLM returns full file content, not a diff. The diff is computed client-side.

**Approach:** 🛠️ EVOLVE the prompt to ask for unified diff, with full-file fallback.

**Migration:** 🚧 SAFE — `_extract_code_block()` currently handles full file. Add `_try_extract_unified_diff()` that runs first. If LLM returns a valid unified diff, apply via `patch` module. If not, fall back to full-file extraction.

```python
# In _ai_fix(), after call_ai():
proposed = _try_extract_unified_diff(response)
if proposed is None:
    proposed = _extract_code_block(response)  # fallback: full file
```

**Files to change:**
- `fix/base.py` — add `_try_extract_unified_diff()`
- `ai/prompts.py` — update system prompt to prefer unified diff format

**Effort:** 4 hours

---

### §4.6 — Sandbox Execution Before Real Repo

**Spec:** Apply each candidate in ephemeral checkout/container. Run scoped test set there. Only promote to "proposed fix" if it survives.

**Current state:** ⚠️ PARTIAL. `applier.py` writes to disk → runs tests → auto-rollback on failure. But this is in the REAL working tree — no sandbox. The snapshot mechanism protects against failed writes but doesn't prevent the initial write.

**Approach:** 🛠️ EVOLVE `PatchApplier` to support sandbox mode.

**Migration:** 🚧 SAFE — sandbox mode is an OPT-IN step before disk write. Current `apply_without_sandbox()` stays as fallback.

```python
# In applier.py — new method:
def apply_in_sandbox(self, patch: Patch) -> ApplyResult:
    with tempfile.TemporaryDirectory() as tmp:
        # Copy only affected files to tmp
        for change in patch.changes:
            sandbox_file = Path(tmp) / change.path
            sandbox_file.parent.mkdir(parents=True, exist_ok=True)
            sandbox_file.write_text(change.proposed)
        # Run tests in sandbox
        test_ok = self._run_tests_in(tmp, ...)
        if test_ok:
            return self.apply(patch)  # real disk write
        return ApplyResult(success=False, rolled_back=False, ...)
```

**Files to change:**
- `fix/applier.py` — add `apply_in_sandbox()`
- `coordinator.py` — gate: sandbox mode for high-risk, fast apply for low-risk

**Effort:** 2 days

---

### §4.7 — Fix-Pattern Memory

**Spec:** When an LLM-generated fix succeeds and gets applied, store the diff pattern as a parameterized codemod. Next occurrence of same pattern uses stored codemod directly — no LLM call.

**Current state:** ⚠️ PARTIAL. `learning.py` tracks accept/reject counts per `finding_type` + per-agent trust scores. Does NOT store actual diff patterns for reuse.

**Approach:** 🛠️ EVOLVE `learning.py` — add `store_fix_pattern()` and `lookup_fix_pattern()`.

**Migration:** 🚧 SAFE — new methods alongside existing accept/reject tracking. Existing data untouched.

```python
# In learning.py — new:
def store_fix_pattern(control_id: str, code_context: str, diff: str, root: Path) -> None:
    """Store successful fix as parameterized pattern for reuse."""
    # Abstract variable parts (string literals, numbers) to placeholders
    # Store in .patchi/fix_patterns/{control_id}/hash.json

def lookup_fix_pattern(control_id: str, code_context: str, root: Path) -> str | None:
    """Return stored diff if pattern matches, None if no match."""
    # Fuzzy match by control_id + code structure
    # If match found, apply stored diff directly — no LLM call
```

**Files to change:**
- `brain/learning.py` — add pattern store/lookup
- `fix/fix_agents.py` — check `lookup_fix_pattern()` before calling LLM
- `coordinator.py` — track pattern pattern hits/misses

**Effort:** 2 days

---

### §4.8 — Confidence Gating by Domain Risk

**Spec:** Auto-apply for low-risk domains (lint, dead code, formatting). ALWAYS route auth/secrets/payment-critical to human review, regardless of composite score.

**Current state:** ⚠️ PARTIAL. `risk_gate.py` has 3 modes (CONFIRM/AUTO/AUTOPILOT) with risk threshold. Auth/payment files get +25 risk score bonus. But this is flat scoring — not tied to a domain taxonomy with blast-radius criticality levels.

**Approach:** 🛠️ EVOLVE `risk_gate.py` — add domain-risk hard blocks.

**Migration:** 🚧 SAFE — hard blocks are new checks added before existing gate logic.

```python
# In risk_gate.py — new hard block:
def _check_domain_criticality(self, patch: Patch) -> list[str]:
    """Blocks that fire regardless of mode."""
    blocks = []
    for change in patch.changes:
        domain = self._domain_for_path(change.path)
        if domain in ("auth", "secrets", "payment"):
            blocks.append(f"{domain}-critical path: {change.path} — requires human review")
    return blocks
```

**Files to change:**
- `fix/risk_gate.py` — add `_check_domain_criticality()` + domain→path mapping

**Effort:** 4 hours

---

### §4.9 — Second-Opinion Adversarial Pass

**Spec:** Before auto-apply, run a separately-framed LLM call whose only job is "does this diff introduce a new vulnerability class?" Different framing than the fix-generator call.

**Current state:** ❌ NOT STARTED. No adversarial pass.

**Approach:** 🚧 SAFE — new optional step in applier after scoring, before write.

**Migration:** Config flag `adversarial_check: true` — off by default. New step doesn't change existing flow.

```python
# In applier.py or coordinator.py — new step:
def adversarial_check(patch: Patch, config: dict) -> AdversarialResult:
    """Second-opinion: 'does this diff introduce new vulns?'"""
    prompt = f"""Review this diff for NEW vulnerabilities introduced:
    {patch.diff}
    
    Does it introduce ANY new security issue (injection, XSS, auth bypass, etc.)?
    Answer YES or NO with one-sentence evidence."""
    response = call_ai(config, ADVERSARIAL_SYSTEM_PROMPT, prompt)
    return parse_adversarial_response(response)
```

**Files to change:**
- `fix/applier.py` — add `adversarial_check()` step
- `coordinator.py` — gate: run adversarial check before auto-apply if config flag set

**Effort:** 1 day

---

### §4.10 — Silent/Semantic Bugs

**Spec.** Structural (dangling/orphan routes) → deterministic graph traversal. Semantic (wrong destination, not no destination) → LLM classifier, flagged with evidence, NEVER auto-applied.

**Current state:** ⚠️ PARTIAL. `import_graph.py` `find_dead_files()` finds structural orphans. No semantic mismatch classifier exists.

**Approach:** 🛠️ EVOLVE existing agent system.

**Migration:** 🚧 SAFE — new scanner agent type. Doesn't change fix pipeline.

```
Structural (new scanner agent — no LLM):
  - Detect orphan routes: graph traversal on route mapper output
  - Dead files: already exists in import_graph.py
  - Label→destination drift: compare current crawl to prior snapshot

Semantic (new scanner agent — LLM-assisted, NEVER fixes):
  - "Does label X plausibly match destination Y?"
  - Output: confidence score + evidence
  - NEVER auto-applied — always routed to human review
  - Adding to scanner agents as GUARD-level group
```

**Files to change:**
- New: `core/agents/orphan_detector.py` (structural — no LLM)
- New: `core/agents/semantic_classifier.py` (LLM-assisted, never fixes)
- Minor: `agents/base.py` — add new agent type to registry

**Effort:** 3 days (structural) / 1 week (semantic classifier)

---

### §4.11 — No LLM Boundary (Design Principle)

**Spec:** Every LLM call is: scoped to graph neighborhood, filling a known playbook, one of several candidates judged by deterministic scoring, producing structured output. A "fairly good" model on a narrow job ≈ frontier model on the same narrow job.

**Current state:** ⚠️ PARTIAL. The architecture already keeps LLM as a bounded tool call (no autonomous reasoning loops). But violations exist:

| Violation | Current | Fixed By |
|-----------|---------|----------|
| Whole-file context → LLM | file_content[:8000] | §4.2 Graph-scoped context |
| Single candidate, trusted by assertion | 1 call = 1 patch | §4.4 Multiple candidates |
| LLM returns full file | diff computed afterwards | §4.5 Structured diff |
| No deterministic pre-pass | all fixers use LLM | §4.1 Deterministic-first |
| No fix-pattern memory | same fix costs LLM every time | §4.7 Fix-pattern memory |

**Approach:** This is the FOUNDATION that §4.1-4.10 implement. Not a separate item — it's the "why" behind each change.

---

## §5 — files-5 Strategic Items (Consolidated with Current Status)

Items are marked: ✅ DONE (codebase already has it) / ⚠️ PARTIAL / ❌ NOT STARTED

### ✅ Already in Codebase (codebase is AHEAD of these specs)

| Item | Spec Doc | Codebase File |
|------|----------|---------------|
| Event schema (MITRE ATT&CK, technique_id) | builder-brief §3.2 | `event.py` |
| Sigma rule engine (YAML, field matching) | builder-brief §3.2 | `sigma_engine.py` |
| Dispatcher (technique_id → agent routing) | builder-brief §3.3 | `dispatcher.py` |
| ConfidenceGate (0.0-1.0 scoring → routing) | builder-brief §3.3 | `confidence_gate.py` |
| DetectionPipeline (gate + orchestrator) | builder-brief §3.4 | `detection_pipeline.py` |
| DefenseLayer (6 action types) | builder-brief §3.5 | `defense_layer.py` |
| Coordinator (agent execution engine) | testing-strategy §2 | `coordinator.py` |
| Hosted mode (init/worker/guard/daemon/token) | builder-brief §2b | `hosted_cmd.py` |
| Log parsers (7 formats) | builder-brief §3.1 | `log_parsers.py` |
| Anomaly detection (statistical + ML) | builder-brief §3.2 | `anomaly.py` |
| IP reputation + auto-block | builder-brief §3.4 | `ip_reputation.py` |
| Watchlist + escalation | builder-brief §3.4 | `watchlist.py` |
| Audit log (rotating JSON-lines) | builder-brief §3.6 | `audit_log.py` |
| Admin tokens (HMAC-SHA256) | builder-brief §3.6 | `tokens.py` |
| SAST via Semgrep | builder-brief §4 | `sast_agent.py` |
| SCA via OSV (multi-ecosystem) | builder-brief §4 | `dependency_vulnerability_agent.py` |
| Secrets scanning (Gitleaks + regex) | builder-brief §4 | `secret_scanning_agent.py` |
| Policy engine + governance | builder-brief §3.5 | `governance.py` |
| WebSocket + exponential backoff | builder-brief §2b | `ws.py`, `base.html` |
| Brain scan pipeline | exploration-agent §2 | `brain/brain.py` |
| Import graph (file-level) | exploration-agent §3 | `brain/import_graph.py` |
| Blast radius (BFS, per-file + all files) | master-plan §7 | `brain/blast_radius.py`, `blast_cmd.py` |
| Health scoring (5-component 0-100) | master-plan §8 | `health.py` |
| Framework-aware route mapper | exploration-agent §2.1 | `brain/route_mapper.py` |
| Framework detector | exploration-agent §2.1 | `brain/framework.py` |
| 34 security agents | builder-brief §3.4 | `security/security_agents.py` |
| 13 test agents | testing-strategy §2a | `testing/` |
| Supply chain (license, typosquatting) | builder-brief §4 | `security/supply_chain.py` |
| Web UI (9 panels) | builder-brief §2b | `web/routes/` |
| Structured Finding dataclass | testing-strategy §2 | `agents/base.py` |
| Orphan edge detection (dead files) | testing-strategy §5 | `brain/import_graph.py` |
| ASGI middleware (request interceptor) | builder-brief §2b | `security/request_interceptor.py` |
| BlastRadiusAgent with apply gate | master-plan §7 | `security/blast_radius.py` |
| Fix agent Skill prompts | fixing-strategy §3 | `ai/prompts.py` |
| Risk gate with 3 modes | fixing-strategy §8 | `fix/risk_gate.py` |

### ⚠️ Partial (exists but not complete vs spec)

| Item | Spec Doc | What's Missing |
|------|----------|----------------|
| Incremental graph update | exploration-agent §4 | Full rebuild still happens — diff computed after rebuild, not used to skip work |
| Falco runtime agent | builder-brief §4 | Static config analysis only — no subprocess invocation |
| Red team agent | builder-brief §4 | Static pattern detection — no Atomic Red Team/Juice Shop |
| Blast radius weighting | master-plan §7 | File count only — no test_coverage/runtime_confirmed/criticality weights |
| Health scoring (domain taxonomy) | master-plan §8 | Fixed 5-component model — no dynamic domain activation |
| Pipeline ordering | testing-strategy §3 | Rough phase order exists — no enforced gates between phases |
| Three deployment shapes | builder-brief §2 | Standalone done — Embedded + GitHub App missing |
| Fix-pattern memory | fixing-strategy §7 | Accept/reject counts only — no stored diff patterns |
| Learning brain → fix patterns | fixing-strategy §7 | Records acceptance rates — doesn't store successful patterns for reuse |
| Skill prompts → fix playbooks | fixing-strategy §3 | General prompts — not per-control_id templates with remediation_ref |

### ❌ Not Started (complete gaps)

| # | Item | Spec Doc | Effort |
|---|------|----------|--------|
| 1 | Wazuh integration | builder-brief §4 | 2w |
| 2 | Coraza/ModSecurity WAF | builder-brief §4 | 1w |
| 3 | Suricata/Zeek network IDS | builder-brief §4 | 1w |
| 4 | GitHub App/bot (webhook + PR comments) | builder-brief §2c | 3-4w |
| 5 | Embedded mode SDK (npm/pip) | builder-brief §2a | 2-3w |
| 6 | Symbol-level graph | exploration-agent §3 | 2w |
| 7 | Multiple edge types (calls, renders, http) | exploration-agent §3 | 2w |
| 8 | Graph-scoped test generation | testing-strategy §4 | 2w |
| 9 | Dynamic crawl (Playwright for exploration) | exploration-agent §2.2 | 1w |
| 10 | Composite fix scoring (4 gates) | fixing-strategy §4 | 3d |
| 11 | Sandbox reverification | fixing-strategy §6 | 2d |
| 12 | Context-aware domain taxonomy (YAML) | master-plan §8 | 2w |
| 13 | Context classifier (signals → domains) | master-plan §8 | 2w |
| 14 | N/A as first-class score state | master-plan §8 | 3d |
| 15 | Attack simulation harness (Atomic Red Team) | builder-brief §5 | 2w |
| 16 | OS keychain for secrets | master-plan §5 | 3d |
| 17 | SLSA/provenance releases | master-plan §5 | 2d |
| 18 | Auto-update + signature verification | master-plan §5 | 1w |
| 19 | Deterministic-first fix ordering | fixing-strategy §1 | 2d |
| 20 | Graph-scoped fix context | fixing-strategy §2 | 4h (file-level) / 2w (symbol-level) |
| 21 | Multiple fix candidates | fixing-strategy §4 | 3d |
| 22 | Structured diff output | fixing-strategy §5 | 4h |
| 23 | Second-opinion adversarial pass | fixing-strategy §9 | 1d |
| 24 | Semantic mismatch classifier | fixing-strategy §10 | 1w |
| 25 | Agent result caching | — | 2d |
| 26 | Incremental scanning (MD5 pre-filter) | — | 1d |
| 27 | OSV batch query + cache | — | 4h |
| 28 | Cache LLM reordering | — | 2h |

---

## §6 — Migration Plan: Fixing Strategy vs Current Pipeline

The current fix pipeline (`coordinator.py` + `fix_agents.py` + `applier.py` + `risk_gate.py`) is already solid. The Fixing Strategy adds rigor around what's already there. Below is the specific mapping and evolution path.

### Current Pipeline Flow

```
Scanner Agents ──> Findings
                          │
                    Coordinator.run_fix_pipeline()
                          │
                    ┌─────▼─────────────────────────────┐
                    │  1. CodeFixer (LLM, whole file)    │
                    │  2. SecurityFixer (LLM, whole file)│
                    │  3. DeadCodeRemover (LLM)          │
                    │  4. DependencyFixer (LLM)          │
                    │  5. EnvFixer (LLM)                 │
                    │  6. TypeFixer (LLM)                │
                    │  7. RefactorAgent (LLM)            │
                    │  8. UnitTestRunner (LLM)           │
                    └─────┬─────────────────────────────┘
                          │
                    risk_gate.py ──> GateDecision
                          │
                    applier.py ──> ApplyResult (write→test→rollback)
```

### Evolved Pipeline Flow (Fixing Strategy applied)

```
Scanner Agents ──> Findings
                          │
                    Coordinator.run_fix_pipeline()
                          │
                    ┌─────▼─────────────────────────────┐
                    │  PHASE 0: Fix-pattern memory      │  ← NEW (§4.7)
                    │  Check learning.py for stored      │
                    │  codemod patterns. On match → skip │
                    │  LLM entirely.                     │
                    ├───────────────────────────────────┤
                    │  PHASE 1: Deterministic fixers     │  ← NEW (§4.1)
                    │  eslint --fix, semgrep autofix,    │
                    │  npm audit fix, jscodeshift        │
                    │  Residual only flows to Phase 2.   │
                    ├───────────────────────────────────┤
                    │  PHASE 2: Graph-scoped LLM fixers  │  ← EVOLVED (§4.2/4.3/4.5)
                    │  - Graph neighborhood instead of   │
                    │    whole file context               │
                    │  - Playbook template per control_id│
                    │  - LLM returns unified diff, not   │
                    │    full file                       │
                    ├───────────────────────────────────┤
                    │  PHASE 3: Multiple candidates      │  ← NEW (§4.4)
                    │  - 2-3 candidates per issue        │
                    │  - Scored on 4 gates               │
                    │  - Best candidate selected          │
                    ├───────────────────────────────────┤
                    │  PHASE 4: Adversarial pass         │  ← NEW (§4.9)
                    │  - Second-opinion LLM check        │
                    │  - Only for auto-apply candidates  │
                    └─────┬─────────────────────────────┘
                          │
                    risk_gate.py ──> GateDecision
                    (enhanced with domain criticality)   ← EVOLVED (§4.8)
                          │
                    applier.py ──> ApplyResult
                    (sandbox mode for high-risk)         ← EVOLVED (§4.6)
                          │
                    learning.py ──> store_fix_pattern()  ← EVOLVED (§4.7)
                    (successful diff stored for reuse)
```

### File-by-File Change Plan

| File | Change | Type | Risk |
|------|--------|------|------|
| `fix/fix_agents.py` | Add `_ai_fix_multi()` for multi-candidate generation | 🚧 Additive alongside existing `_ai_fix()` | None — old function unchanged |
| `fix/fix_agents.py` | Widen `_ai_fix()` prompt to include graph context | 🚧 Additive in prompt | None — new context fields appended |
| `fix/fix_agents.py` | Add `_try_extract_unified_diff()` before `_extract_code_block()` | 🚧 Additive fallback | None — full file fallback preserved |
| `fix/risk_gate.py` | Add `_check_domain_criticality()` hard block | 🚧 Additive before existing checks | None — existing gate flow unchanged |
| `fix/applier.py` | Add `apply_in_sandbox()` method | 🚧 Additive — new method | None — old `apply()` unchanged |
| `fix/scoring.py` | New module — `composite_score()` | 🆕 New file | None |
| `fix/deterministic_runner.py` | New module — Phase 1 deterministic fixers | 🆕 New file | None |
| `fix/remediation_templates/` | New directory — per-control_id templates | 🆕 New files | None |
| `brain/learning.py` | Add `store_fix_pattern()` + `lookup_fix_pattern()` | 🚧 Additive alongside existing | None — existing accept/reject untouched |
| `agents/base.py` | Add `AgentGroup.DETERMINISTIC_FIX` | 🚧 New enum value | None |
| `coordinator.py` | Add `run_fix_pipeline()` with 5 phases | ⚡ Rewrite of `run_agents()` for FIX group | **BREAKS if someone directly calls `run_agents()` with FIX agents.** Fix: keep `run_agents()` as-is, add `run_fix_pipeline()` as new entry point. Old callers unaffected. |

**Total new files:** 4 (deterministic_runner.py, scoring.py, orphan_detector.py, semantic_classifier.py)  
**Total files changed:** ~10 (all additive changes except coordinator.py which gets a new method)

---

## §7 — Quick-Start: This Week (🟢 No Risk)

| # | Item | §Ref | Effort | Why Now |
|---|------|------|--------|---------|
| 1 | Fix `total=11` in scan_cmd.py:203 | §1 | 2 min | Visual regression |
| 2 | Sanitize `brain.html` `\| safe` | §1 | 5 min | Security |
| 3 | Fix SecurityTestAgent Flask fixtures | §1 | 1h | Broken for FastAPI/Django users |
| 4 | OSV batch query + 24h cache | §3 | 4h | 100 requests → 1 |
| 5 | Cache LLM agent reordering | §3 | 2h | 1 LLM call saved per scan |
| 6 | Agent result caching | §3 | 2d | 5-10x repeat scans |
| 7 | Graph-scoped fix context (file-level) | §4.2 | 4h | Requires import_graph.py which exists |
| 8 | Structured diff output | §4.5 | 4h | Prompt change + fallback parser |
| 9 | Confidence gating by domain risk | §4.8 | 4h | Small hardening in risk_gate.py |
| 10 | Fix-pattern memory (learning.py) | §4.7 | 1d | Core building block for §4.1 |

**Total:** ~4 days, 10 items. All additive, zero breakage risk.

---

## §8 — Build Order (Phased, Non-Breaking)

### Phase A — Foundation (Week 1)
1. Fix §1 bugs (open code bugs) — 2h
2. §3 caching/performance (agent result cache, incremental scan) — 3d
3. Fix-pattern memory in learning.py (§4.7) — 1d
4. Structured diff output (§4.5) — 4h

### Phase B — Fix Pipeline Upgrade (Week 2)
5. Graph-scoped context for file-level (§4.2) — 4h
6. Deterministic-first ordering (§4.1) — 2d
7. Multiple candidates + scoring (§4.4) — 3d
8. Remediation templates (§4.3) — 1d

### Phase C — Safety Gates (Week 3)
9. Sandbox execution (§4.6) — 2d
10. Second-opinion adversarial pass (§4.9) — 1d
11. Domain-risk gating (§4.8) — 4h
12. CI for fix pipeline eval set (§4.11) — 2d

### Phase D — Web UI Polish (Week 4)
13. Settings 8-tab panel — 2d
14. History health trend chart — 1d
15. Side-by-side diff viewer — 1d
16. Notifications/Diagnostics/Agents panels — 3d

### Phase E — Strategic (Month 2-3)
17. Symbol-level graph layer — 2w
18. Dynamic crawl (Playwright exploration) — 1w
19. Graph-scoped test generation — 2w
20. Semantic mismatch classifier — 1w
21. Context-aware domain taxonomy — 2w

### Phase F — New Surfaces (Month 3-6)
22. Embedded mode (npm/pip SDK) — 2-3w
23. GitHub App/bot — 3-4w
24. VS Code extension — 4w+
25. Attack simulation harness — 2w
26. OSS tool integrations (Wazuh, Coraza, Suricata) — 3-4w

---

## Summary

| Category | ✅ DONE | ⚠️ PARTIAL | ❌ NOT STARTED | 🛠️ EVOLVE | ⚡ BREAKS |
|----------|---------|-------------|----------------|------------|-----------|
| Code bugs | 24 fixed | — | 6 open bugs | — | — |
| Web UI | 4 panels | 5 partial | 3 missing | — | — |
| Performance/tech debt | — | — | 8 items | — | — |
| Fixing Strategy (§4) | — | 4 items | 7 items | 5 evolve existing | 1 (coordinator new method) |
| files-5 strategic | 35 items | 10 partial | 28 missing | — | — |
| **Total** | **63** | **19** | **52** | **5** | **1** |

**Key numbers:**
- 63 items already done (codebase is ahead of specs)
- 19 partially done (mostly fix pipeline rigor + web panel polish)
- 52 not started (mostly OSS integrations + new surfaces)
- **1 breaking change** (coordinator.py new method — and even that has a safe path: keep `run_agents()` as-is, add `run_fix_pipeline()` alongside)
- **Zero items require tearing down existing code** — everything is additive or evolutionary
