# Patchi Implementation Roadmap

**Generated:** 2026-07-04  
**Based on:** Master Plan (PATCHI_MASTER_PLAN.md) gap analysis  
**Current state:** All 40+ security agents built, 770+ tests passing, files-5 architecture planning complete

---

## Phase 1: Event System + Triage Agent (NOW)

Build the foundational event schema that everything else emits into, plus the missing Triage Agent.

| # | Task | Est. Effort | Depends On |
|---|------|-------------|------------|
| 1.1 | Event schema (`Event`, `EventSource`, `Severity`, `TechniqueID` types) | 1 day | — |
| 1.2 | Event bus (in-memory pub/sub, async handlers, rate-limiting) | 2 days | 1.1 |
| 1.3 | Event normalization layer (raw signal → `Event` envelope) | 1 day | 1.1 |
| 1.4 | Unify governance + hosted audit logs under common schema | 1 day | 1.1 |
| 1.5 | TriageAgent — anomaly detection over event stream (z-score/EWMA) | 2 days | 1.2 |
| 1.6 | Wire existing agents to emit `AgentResult` as `Event` objects | 1 day | 1.2 |

**Exit criteria:** All 770 existing tests pass; a script can publish events and a subscriber receives them; TriageAgent detects a statistically anomalous event and creates a `Finding`.

---

## Phase 2: Always-On Detector Pipeline

| # | Task | Effort | Depends On |
|---|------|--------|------------|
| 2.1 | Sigma rule loader + engine (parse `.yml` rules, match against events) | 3 days | 1.2 |
| 2.2 | Curated Sigma subset for Patchi agents (100-200 rules) | 3 days | 2.1 |
| 2.3 | Dispatcher (routes `technique_id` + confidence → agent, rate-limits) | 2 days | 1.2, 2.1 |
| 2.4 | Standalone detector daemon (watches log dir / syscall pipe) | 2 days | 1.2, 2.1 |
| 2.5 | Wazuh log ingestion wrapper (subprocess or socket) | 2 days | 2.4 |
| 2.6 | Atomic Red Team harness (Docker target ranges + CI runner) | 3 days | 1.2, 2.3 |

**Exit criteria:** Standalone detector can process a Wazuh JSON log line, match 3+ Sigma rules, dispatch to the correct agent, and log the action; Juice Shop atomic regression passes for Injection Agent.

---

## Phase 3: Blast Radius 2.0

| # | Task | Effort | Depends On |
|---|------|--------|------------|
| 3.1 | Symbol-level dependency graph (AST-based, not file-level) | 4 days | — (parallel with 1-2) |
| 3.2 | Weight the graph (test coverage from CI, criticality tags) | 2 days | 3.1 |
| 3.3 | Damage vs. repair graph comparison | 3 days | 3.1, 3.2 |
| 3.4 | Blast radius visualization (Konva.js overlay: red/amber/green) | 2 days | 3.1 |
| 3.5 | Feed into fix-scoring loop (iterative fix ranking) | 2 days | 3.3, 1.2 |

**Exit criteria:** `p blast src/auth.py` shows symbol-level dependencies with weighted risk; `p fix` proposes multiple candidates ranked by composite score.

---

## Phase 4: Context-Aware Scoring

| # | Task | Effort | Depends On |
|---|------|--------|------------|
| 4.1 | Signal collector (extract domain-relevant signals from codebase) | 2 days | — (parallel) |
| 4.2 | Domain taxonomy YAML definitions (start with Local Tool, Backend API, Frontend, Supply Chain) | 3 days | 4.1 |
| 4.3 | Context classifier (heuristic + AI fallback for ambiguous signals) | 3 days | 4.1, 4.2 |
| 4.4 | Domain activation engine (active/N/A/unclear states) | 2 days | 4.2, 4.3 |
| 4.5 | Weighted scoring formula (Σ domain_weight × domain_score) | 1 day | 4.4 |
| 4.6 | "Explain my score" CLI output + dashboard surface | 2 days | 4.5 |

**Exit criteria:** `p security score` outputs "Supply Chain: 40/100, Backend Auth: N/A" etc.; Patchi self-scan shows meaningful scores; CLI output explains why each domain was activated or not.

---

## Phase 5: Security-of-the-Security-Tool

| # | Task | Effort | Depends On |
|---|------|--------|------------|
| 5.1 | Sandbox dynamic rule loading (subprocess isolation) | 2 days | — |
| 5.2 | OS keychain integration for hosted-mode API keys | 2 days | — |
| 5.3 | Auto-update with signature verification | 3 days | — |
| 5.4 | Self-scan in CI (Dependency + Secrets agents on Patchi's own repo) | 1 day | — |
| 5.5 | Hash-chained audit log export | 2 days | 1.1 |

**Exit criteria:** API keys stored in OS keychain; auto-update verifies GPG signatures; CI self-scan passes.

---

## Phase 6: Embedded Mode + GitHub App

| # | Task | Effort | Depends On |
|---|------|--------|------------|
| 6.1 | Extract embedded SDK (npm/pip middleware wrapper around Core) | 3 days | 1.2, 2.3 |
| 6.2 | GitHub App authentication + webhook receiver | 3 days | — |
| 6.3 | PR commenter + required-check integration | 2 days | 6.2, 2.3 |
| 6.4 | Docker Compose standalone deployment template | 1 day | 2.4 |

**Exit criteria:** `pip install patchi-embedded` gives a FastAPI middleware that runs detector in-process; GitHub App installs on a repo and comments on PRs with Dependency + Secrets reports.

---

## Phase 7: Public Metrics & Ecosystem

| # | Task | Effort | Depends On |
|---|------|--------|------------|
| 7.1 | Self-scan badge generator (SVG + README snippet) | 1 day | 4.5 |
| 7.2 | Community taxonomy contribution guidelines + CI validation | 2 days | 4.2 |
| 7.3 | Published detection rate / FP rate from atomic harness | 2 days | 2.6 |
| 7.4 | Sigma rule contribution guide for Patchi | 1 day | 2.1 |

**Exit criteria:** Badge in README shows live self-scan score; community can submit taxonomy PRs with CI checks.

---

## Risk & Dependencies

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| Wazuh/Suricata setup heavy for solo devs | Medium | Make Sigma engine work standalone first (no Wazuh required); add Wazuh as optional upgrade path |
| Sigma rule corpus too generic for agent-level routing | Low | Curate a Patchi-specific subset; community can extend |
| Atomic Red Team Docker dependencies complex | Medium | Start with Python-only atomic test harness; add Docker step when proving full pipe |
| Symbol-level graph hard to build accurately | Medium | Start with file-level + function-level mixed; accuracy improves over time |
| License conflicts with GPL tools | Low | All tools invoked as subprocesses (not statically linked) — standard FOSS practice |

---

## Build Sequence (First 4 Weeks)

```
Week 1: Phase 1 — Event schema + TriageAgent
Week 2: Phase 2 — Sigma engine + dispatcher + first atomic harness
Week 3: Phase 3 — Symbol-level blast radius + weighted graph
Week 4: Phase 4 — Context taxonomy + scoring + CLI output
```

Phase 5-7 after core stability confirmed.

---

## files-5 Architecture — Next Implementation Phases

| Phase | Component | Description | Depends On |
|-------|-----------|-------------|------------|
| 1 | Governor State Machine | Pipeline phase enforcement (SCAN→TEST→FIX→REVERIFY) wrapping Coordinator | Coordinator |
| 1 | SymbolGraph | Tree-sitter AST parsing → function/class/route-level node graph | — |
| 1 | Incremental Updates | SQLite-backed graph with patch diff (not full rebuild) | SymbolGraph |
| 2 | Graph-Scoped Test Gen | Blast radius v2 using SymbolGraph for test generation scope | Phase 1 |
| 2 | Enhanced Blast Radius | Symbol-level impact analysis (was file-level only) | Phase 1 |
| 3 | Standalone Docker | Containerized deployment with all deps | Phase 1 |
| 3 | Embedded SDK | pip/npm middleware wrapper | Phase 1 |
| 3 | GitHub App | PR commenting + checks | Phase 1 |

**Principle:** All additive — Governor wraps Coordinator, SymbolGraph parallels ImportGraph, SQLite alongside JSON memory.