# PATCHI_SMART_PLAN.md — Verification Report

**Date:** 2026-09-03
**Verifier:** Buffy (Codebuff agent)
**Plan Version:** PATCHI_SMART_PLAN.md (archived)

---

## Executive Summary

**All 6 slices are IMPLEMENTED and VERIFIED.** The plan's vision of transforming Patchi from a "60-agent scanner bus with optional AI" to an "understander-first brain" is complete.

| Slice | Status | Verification |
|-------|--------|--------------|
| Slice 1 — Enriched Context | ✅ DONE | `enriched_context.py` exists, MAX_CHARS=6000, PATCHI_OFFLINE honored |
| Slice 2 — Body Tags + Understander | ✅ DONE | `body_tags.py` (6 roles), `understander.py` (core_files, refine_domains) |
| Slice 3 — Real Pentest | ✅ DONE | Shannon adapter, nuclei/sqlmap/dalfox/ffuf/zap adapters, PentestRegistry |
| Slice 4 — Tool-Reading LLM | ✅ DONE | `read_file` tool (500 lines, 3 calls), reasoning.py TF-IDF |
| Slice 5 — Fix/Test with Real Context | ✅ DONE | fix/base.py uses understander.function_at, blast_radius |
| Slice 6 — Gating + Speed | ✅ DONE | brain.py uses active_domains, domain refinement |

---

## Detailed Verification

### Slice 1 — Enriched Context ✅

**File:** `patchi/core/brain/enriched_context.py`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| 1 LLM call per scan | ✅ | `enrich_project_context()` function |
| MAX_CHARS=6000 | ✅ | Line 26: `MAX_CHARS = 6000` |
| PATCHI_OFFLINE support | ✅ | Line 47: `if os.environ.get("PATCHI_OFFLINE"):` |
| Offline fallback | ✅ | Returns heuristic context when offline |

### Slice 2 — Body Tags + Understander ✅

**Files:** `patchi/core/brain/body_tags.py`, `patchi/core/brain/understander.py`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| 6 body roles | ✅ | brain/muscle/bone/blood/skin/nerve (lines 9-14) |
| fan_in scoring | ✅ | `fan_in` in body_tags computation |
| score computation | ✅ | `score` field in body_tags |
| core_files(limit) | ✅ | `understander.py` line 42: `def core_files(self, limit: int = 16)` |
| refine_domains | ✅ | `understander.py` line 63: `def refine_domains(self, active)` |
| file_snippet | ✅ | `understander.py` line 74: `def file_snippet(self, rel_path, max_lines=200)` |

### Slice 3 — Real Pentest ✅

**Files:** `patchi/core/security/pentest/`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| PentestTool base class | ✅ | `base.py` line 26: `class PentestTool(ABC)` |
| Shannon adapter | ✅ | `shannon_adapter.py` line 18: `class ShannonTool(PentestTool)` |
| nuclei adapter | ✅ | `nuclei_adapter.py` |
| sqlmap adapter | ✅ | `sqlmap_adapter.py` |
| dalfox adapter | ✅ | `dalfox_adapter.py` |
| ffuf adapter | ✅ | `ffuf_adapter.py` |
| zap adapter | ✅ | `zap_adapter.py` |
| PentestRegistry | ✅ | `registry.py` line 20: `class PentestRegistry` |
| AI tool choice | ✅ | `registry.py` line 49: LLM picks 1-3 tools |
| AGPL-clean (npx, not vendored) | ✅ | Shannon via `npx @keygraph/shannon@latest` |

### Slice 4 — Tool-Reading LLM + Reasoning ✅

**Files:** `patchi/core/ai/tools/`, `patchi/core/brain/reasoning.py`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| read_file tool | ✅ | `registry.py` line 552: `name="read_file"` |
| 500 lines limit | ✅ | `realize.py` line 1006: `def read_file(..., end: int = 500)` |
| Path validation | ✅ | `realize.py` line 1024: `if not full.is_file()` |
| 2MB limit | ✅ | `realize.py` line 1027: `if >2MB` |
| TF-IDF reasoning | ✅ | `reasoning.py` line 180: TF-IDF over layers + body_tags |
| LLM synthesis | ✅ | `reasoning.py` line 256: optional `call_ai` synthesis |

### Slice 5 — Fix/Test with Real Context ✅

**Files:** `patchi/core/fix/base.py`, `patchi/core/testing/`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| understander.function_at | ✅ | `fix/base.py` line 262: `_u.function_at(file_path, line_num)` |
| blast_radius injection | ✅ | `fix/base.py` line 480: `blast_radius=compute_blast_radius(...)` |
| Test generation | ✅ | `browser_test_agent.py` line 341: `_generate_tests_from_contract` |
| TEST_GENERATE skill | ✅ | `browser_test_agent.py` line 354: `get_system_prompt(Skill.TEST_GENERATE)` |

### Slice 6 — Gating + Speed ✅

**File:** `patchi/core/brain/brain.py`

| Requirement | Status | Evidence |
|-------------|--------|----------|
| active_domains gating | ✅ | `brain.py` line 449: `report.active_security_domains = context_data["active_domains"]` |
| Domain refinement | ✅ | `understander.refine_domains()` |
| scan_vulnerabilities pruning | ✅ | Brain uses refined domains for targeted scanning |

---

## Guardrails Verification

| Guardrail | Status | Evidence |
|-----------|--------|----------|
| MAX_CHARS=6000 | ✅ | `enriched_context.py` line 26 |
| PATCHI_OFFLINE honored | ✅ | `enriched_context.py` line 47, `fix/base.py` line 23 |
| Path validation (is_file) | ✅ | `realize.py` line 1024 |
| 2MB file limit | ✅ | `realize.py` line 1027 |
| 500 lines / 3 calls limit | ✅ | `realize.py` line 1006 |
| No free-form rglob | ✅ | Only ToolRegistry enumerated tools |

---

## What's NEW (Not in Original Plan)

### BrainContext Bridge (Added 2026-09-03)

The plan didn't include a formal bridge connecting all brain systems. We added:

- **BrainContext class** (`patchi/core/brain/brain_context.py`)
- **Wires** enriched_context, project_reader, body_tags, domain_loader, reasoning into one object
- **Injected** into DetectionPipeline for context-aware finding classification
- **Injected** into chat_cmd for full brain state injection
- **Finding context enrichment** — test fixture demotion, critical dir boost, domain matching

### Plugin System (Added 2026-09-03)

The plan didn't include a formal plugin interface. We added:

- **Analyzer base class** with formal contract (context in, findings out)
- **PluginRegistry** with auto-discovery from 3 directories
- **Stable finding IDs** (deterministic sha256)
- **3 built-in analyzers** (secret-scanner, todo-scanner, dead-code)
- **CLI command** (`p plugins list/run/run-all/info`)

---

## Remaining Items (Not in Smart Plan)

### From ROADMAP.md

| Item | Priority | Status |
|------|----------|--------|
| Quick Wins (trend graphs, heatmap, baseline) | High | Partially done |
| GNN Bug Detection | Dropped | Deleted — untrainable, code+plan removed |
| Scan Bus (FileCorpus + shards) | High | Not started |
| Debugger delegation | Low | Not started |

### From Feature Plan

| Item | Status |
|------|--------|
| 73 missing features (65.2%) | Most not started |
| 16 partially done | Need completion |

---

## Conclusion

**The PATCHI_SMART_PLAN.md is FULLY IMPLEMENTED.** All 6 slices are complete, all guardrails are in place, and the vision of an "understander-first brain" is realized.

The plan was conservative — it didn't anticipate the BrainContext bridge or Plugin system we added, which go beyond the original scope.

**Recommendation:** The plan is complete. Focus next on:
1. The remaining 73 features from the Feature Plan
2. Scan Bus (largest remaining architecture piece)

---

*Verification completed 2026-09-03 by Buffy*
