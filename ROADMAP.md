# ROADMAP — Patchi (from uncompleted planning docs)

> Single source for what's left. Generated 2026-09-02 by consolidating `docs/planning/` (43 MDs) → `docs/archive/` (completed) + this file (uncompleted). Every item below is still ❌/⚠️ per its source doc at time of consolidation.

---

## 1. Feature Expansion (docs/planning/PATCHI_FEATURE_PLAN.md — 112 features)

**Status in source:** 23 ✅, 16 ⚠️, **73 ❌ missing** (65.2%). This doc is the master feature ledger.

**Remaining by section:**

| Section | Missing highlights |
|---|---|
| **1 Static Analysis** (9 missing) | 1.1.1 Strict Mode Enforcer, 1.1.3 Incremental Type Checking, 1.1.4 Type Error Categorization, 1.2.2 Custom Rule Engine, 1.2.3 Zero-Warnings Policy, 1.3.2 Layer Enforcement, 1.3.3 Import Graph Visualization |
| **2 Dead Code & Deps** (5 missing) | 2.1.2 Unused Variable/Import Cleanup, 2.1.3 Unreachable Code Paths, 2.1.4 Feature Flag Archaeology, 2.2.2 Duplicate Dependency Finder, 2.2.4/5 Outdated Report / Supply Chain Risk |
| **3 Route & API** (6 missing) | 3.1.4 Missing Routes (404), 3.1.5 Orphan Endpoints, 3.1.6 Method Mismatch, 3.1.7 Path Parameter Drift, 3.2.1-3 Schema/Env validation, 3.3 SPA Route Inventory |
| **4 Security** (1 missing) | 4.1.7 Insecure Randomness `Math.random()`, 4.2.4 Rate Limiting Audit |
| **5 Dynamic/Runtime** (11 missing) | All of 5.x: unhandledRejection tracker, memory leak, detached DOM, event leak, bundle size, startup time, API fuzzer (EvoMaster), boundary/race/chaos testing |
| **6 Testing** (6 missing) | 6.1.1 Coverage-Guided Prioritization, 6.1.2 Branch Coverage, 6.1.3 Mutation Testing (universalmutator), 6.1.4 Flaky Detection, 6.2.2 Contract Test Generation |
| **7 Refactoring** (7 missing) | Auto-fix type errors, dependency sorting, modernization codemods, catch block auditor, domain error classes, resource leak detection |
| **8 Frameworks** (8 missing) | Vue/Svelte/Angular/Solid checks, Go/Rust/GraphQL analysis, Vite/Turborepo/Docker validators |
| **9 Reporting** (3 missing) | Trend Graphs, Risk Heatmap, Tech Debt Timeline |
| **10 CI/CD** (10 missing) | GitHub Action, GitLab CI, pre-commit hook, branch protection gates, baseline locking, gradual enforcement, ignore expiry, auto-ticket |
| **11 Advanced** (7 missing) | AI Bug Prediction, NL Query, Cross-Repo Analysis, Runtime Telemetry, SBOM (cdxgen/syft), License Compliance, i18n audit |

**Phases per plan:**
- **Phase 1 Quick Wins 1-2w:** Trend graphs, heatmap, baseline locking, ignore expiry, blame, insecure randomness, catch auditor
- **Phase 2 Tool Integration 3-4w:** deadcode orchestrator, EvoMaster fuzzer, SBOM, circular deps, contract diff, mutation, supply chain
- **Phase 3 Deep Framework 3-4w:** Frontend framework checks, codemods, SPA, build tools, resource leaks
- **Phase 4 Runtime 4-6w:** memory profiling, race/chaos, license, i18n, bug prediction, NL query, cross-repo

---

## 2. GNN Bug Detection — DELETED

**Status:** Deleted — untrainable without a labeled corpus; all code
(`agents/gnn_detector.py`, `gnn_models.py`, `cpg_extractor.py`,
`graph_normalizer.py`, `vulnerability_classifier.py`,
`tools/fetch_vuln_model.py`, `tests/test_gnn_*`, `tests/test_cpg_extractor.py`)
and the 28-day implementation plan removed. Do not re-add.

---

## 3. Understander-First Follow-ups (docs/planning/patchi_plans/MASTER_ROADMAP.md — honest sizing)

| Item | Size | Note |
|---|---|---|
| CLI Theme adoption (1243 `print()` → semantic helpers) | XL–XXL | Ongoing per design doc |
| Scan Bus `FileCorpus + safe_rglob + shards + QueueRunner + FindingBus` | XL–XXL | P2 done: QueueRunner + FindingBus drain in coordinator (per-file sharding waits on scope-honoring agents) |
| CI/PR bundle `Finding model + stable id + Baseline+delta #1 + --since + SARIF + fix --safe-all` | M each | Done: renderer registry, `p scan --since`, `p fix --safe-all`, SARIF unified |
| Dynamic security checks (42 controls tagged `check_method: dynamic`, 0 impl) | — | Needs process-launch primitive (same as debugger) |
| Debugger delegation brief (Python-first, DAP client) | L–XL | Brief ready `debugger-delegation-brief.md`, not started |
| Language expansion `_parse_html` → tree-sitter, phases 5,7,8,9,10 | S–M / unknown | Half of 10-phase plan verified done; remainder unverified |

---

## 4. Other Planning Still Open

| Source | What |
|---|---|
| `docs/planning/_planning_docs/LANGUAGE_EXPANSION_PLAN.md` / `docs/planning/language-expansion-plan.md` | 10-phase language holes: use to close remaining languages |
| `docs/planning/_planning_docs/ROADMAP.md`, `docs/planning/patchi_plans/MASTER_ROADMAP.md:P2` | Language expansion remainder |
| `docs/planning/patchi_plans/PATCHI_PLAN_v0.8.md` + `LINKAGE_GUIDE.md` | Decision log + cross-cutting linkage guide — read before editing X |
| `docs/planning/patchi_plans/debugger-delegation-brief.md`, `domain-reset-delegation-brief.md` | Ready-to-send delegation prompts (neither started) |
| `docs/planning/hosted-mode-2.0-pipeline.md`, `defense-and-repo-integration-plan.md`, `polyglot-pipeline-plan.md`, `super-agent-plan.md` | Hosted/defense/polyglot/super-agent pipelines — not started |
| `docs/planning/files-5/patchi-testing-strategy-v2.md` + `docs/planning/_planning_docs/TESTING_PLAN.md` | Testing strategies still to implement |

---

## 5. Repo Structure Now

```
docs/
  ARCHITECTURE.md, CLI.md, WEB.md, OVERVIEW.md, DEPLOYMENT.md, LANGUAGE_SUPPORT.md, STRIDE.md
  planning/          ← single planning folder (43 MDs consolidated here)
    PATCHI_FEATURE_PLAN.md (source for §1),
    _planning_docs/*, patchi_plans/*, files-5/*
    defense-and-repo-integration-plan.md, hosted-mode-2.0-pipeline.md, ...
  archive/           ← completed plans (do not edit)
    BUILD_MAP.md, AUDIT_STUBS..., PATCHI_V2_UPGRADE_PLAN.md, PATCHI_SMART_PLAN.md,
    RELEASE-v0.7.0.md, BUILD_PLAN.md, PATCHI_FULL_AUDIT_*, PATCHI_MASTER_* ...
ROADMAP.md           ← this file (root) — single roadmap from uncompleted
```

*Source docs retained verbatim in `docs/planning/`; archive is `git mv` so history preserved.*

---

## 6. Next Actions (in priority order from consolidated plan)

1. **Quick Wins (Day 1-2)** §4.1.7 + §7.2.1 + §10.3.2 + §10.2.1 + §9.1.2 from Feature Plan
2. **Dead Code Orchestrator** (§2.1.1)
3. **Scan Bus** — only after Quick Wins, as it's the largest
4. **Debugger vs Dynamic checks** — share process-launch primitive, sequence together

