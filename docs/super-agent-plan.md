# Patchi Super-Agent — Architecture Plan

> Goal: Transform Patchi from a batch scanner pipeline with bolted-on AI calls
> into an **always-on AI super-agent** that understands the codebase, acts
> proactively, and stays in scope via user-defined guard rails.

---

## The Core Problem (confirmed in code)

- `Brain.scan()` always runs the **full 8-phase pipeline** from scratch. The only
  incrementality is a per-file hash cache for `FileInfo` parsing — but the
  *knowledge* (routes, graph, contracts, summaries) is recomputed and discarded
  every run.
- There is **no project identity** — nothing encodes "this project is supposed to be X."
- The App Contract (`contract.py`) exists but is **informational only** — no gate
  blocks a violating change, and it has no architecture/style rules.
- `BrainWatcher` detects changes and rescans, but **never acts** on them.

---

## Three New Pillars

### Pillar 1 — Layered Brain (the "complex brain system")

Break the codebase into persistent **layers** so context is retrieved, not re-read.

```
Layer 4: PROJECT    → purpose, stack, conventions, guard rails
Layer 3: FLOWS      → critical paths (contract flows) + their layers
Layer 2: SUBSYSTEMS → "auth", "data", "api", "ui" (semantic groups)
Layer 1: MODULES    → directory-level (src/auth/, src/api/) — cached summaries
Layer 0: FILES      → FileInfo (already exists)
```

Each layer carries:
- A **summary** (heuristic now, LLM/embedding later) — agent reads a short summary, not raw source
- **Layer dependencies** (derived from the import graph — A imports B ⇒ Layer A depends on Layer B)
- A **validity hash** — invalidated only when a child file's public API changes

**Fast context retrieval:** when the agent needs context on "auth", it loads
`Layer(auth).summary` + its direct dependency summaries. It never re-reads the whole repo.

**Incremental update (the speed win):**
- File save → re-parse **that one file** only → update `Layer 0`
- If its **exports/signatures** changed → invalidate `Layer 1` summary → propagate up one level
- Layers whose children didn't change are **never touched**

Storage: extend the existing `.patchi/` JSON system — add `layers.json`
(layer graph + summaries) alongside `brain.json`. No new database.

### Pillar 2 — Guard Rails (Project Charter)

The user declares what the project *should be*. Both humans and agents get flagged on drift.

**Input:** `p charter "This is a Flask+React monorepo. Frontend must never import
backend DB modules. All API routes need tests. No hardcoded secrets. Services under 80 lines."`

**Parsed into structured rules** (NL → structured, stored in `.patchi/charter.json`):
- `stack`: {languages, frameworks} — drift if a new unexplained framework appears
- `boundaries`: forbidden import edges (e.g. `ui → data`)
- `conventions`: naming, max file/function size, required test coverage per route
- `security`: no hardcoded secrets, no `pickle`/`eval`, parameterized queries

**Three enforcement points:**
1. **Pre-commit (humans):** `p scan --staged` checks changed files against charter → blocks commit on violation
2. **Watch mode (realtime):** a changed file that violates a boundary is flagged immediately
3. **Governor (agents):** charter rules become extra **acceptance criteria / escalation triggers** — an agent fix that breaks a boundary is auto-rejected

**Drift detection:** the Layered Brain's actual state is continuously compared to the
charter. A mismatch (e.g. frontend imported a backend module) becomes a finding
tagged `charter-drift` with the specific rule it broke.

### Pillar 3 — Reasoning + Proactive Agent

On top of Pillars 1+2, replace the "scan → find → fix" pipeline with an
**event-driven agent**:

| Trigger | Action |
|---|---|
| File saved | Update Layer 0 → invalidate affected layers → auto-fix imports/format if safe |
| Import added | Check guard rails → "you imported `pickle` — deserialization risk" |
| Function added | DuplicateScanner on that function → "90% similar to `validate_email()` in `utils/`" |
| Signature changed | Trace callers via Layer deps → "updating 3 callers in `auth.py`, `profile.py`" |
| Test fails | Map failure to recent changes → "failing because you changed `parse_user()` return shape" |
| `p ask "..."` | Query Layered Brain → answer from layer summaries, not raw source |
| Pre-commit | "This change affects 14 files, 2 contracts, 1 security concern" |

All actions are **change-scoped** — the agent only ever touches what you changed.

---

## Status (verified against code, 2026-08-26)

| Phase | Pillar | Status | Evidence |
|---|---|---|---|
| 0 — Foundation (Layered Brain) | Pillar 1 | ✅ Done | `patchi/core/brain/layered_brain.py` exists; `Layer` model + builder on `import_graph` |
| 1 — Incremental updates | Pillar 1 | ✅ Done | `brain.py:375` calls `build_or_update` (real incremental path); falls back to full build only on exception |
| 2 — Guard Rails (Charter) | Pillar 2 | ✅ Done | `patchi/core/security/charter.py`; `brain.py:409` runs `check_charter` drift each scan; `p charter` present |
| 3 — Reasoning Engine | Pillar 3 | ✅ Done | `patchi/core/security/reasoning.py`; `p ask` / `p why` / `p explain` wired in `reason_cmd.py` |
| 4 — Proactive Actions | Pillar 3 | ✅ Done | `patchi/core/brain/proactive.py` (`analyze_change`, imports/dead_code/signature_callers); `watch_cmd.py` applies fixes on save; `p impact` blast-radius present; **+ SAST verify of applied fixes added (opt-in `auto_fix.verify_sast`)** |
| 5 — Learning | Pillar 3 | ✅ Done | `learning.py` (`record_acceptance/rejection`, `should_suggest`, `get_agent_trust`, `record_fix_pattern`); personalization loop wired into fix suggestions |

**Net:** All 6 phases are implemented in code. The only addition made during the
2026-08-26 implementation pass was closing the proactive-fix loop: applied fixes
in `p watch` are now optionally re-checked against Bandit + Semgrep via
`tool_verify.high_findings_on_file` (`watch_cmd.py`), escalating any
HIGH/CRITICAL regression to `mem.save_issue`. Gated behind `auto_fix.verify_sast`
(default off) because Semgrep is ~120s/file in this sandbox — enabling it trades
watch-mode latency for deeper verification.

---

## Implementation Roadmap

**Phase 0 — Foundation (1–2 days)**
- Add `Layer` dataclass + `layered_brain.py` builder on top of existing `import_graph` + `FileInfo`
- Generate `layers.json` at end of `Brain.scan()` (additive, doesn't break existing flow)
- Module/Subsystem grouping heuristics (directory structure + import clusters)

**Phase 1 — Incremental updates (2–3 days)**
- `BrainWatcher` → on change, update only the changed `Layer 0` + invalidate ancestors
- `mark_brain_stale` extended to record *which layers* are stale
- `p scan` becomes a no-op for unchanged layers (reads cached summaries)

**Phase 2 — Guard Rails (2–3 days)**
- `charter.py`: NL parser → structured rules → `.patchi/charter.json`
- `p charter` CLI command (set / show / check)
- Boundary + convention checks wired into scanner findings as `charter-drift`
- Pre-commit hook generation that actually runs `pre-commit install`

**Phase 3 — Reasoning Engine (3–5 days)**
- `reasoning.py`: given a change-set + Layered Brain → structured impact analysis
- `p ask` / `p explain` / `p why` NL commands
- Charter violations surface in watch mode + Governor escalation

**Phase 4 — Proactive Actions (3–4 days)**
- Safe auto-fix on save (imports, format, dead code) behind a flag
- Signature-change caller update (using Layered Brain caller map)
- Change-impact report command

**Phase 5 — Learning (ongoing)**
- Track user overrides → personalize warnings
- Adapt conventions from observed patterns

---

## What Stays vs Changes

**Stays:** scanners, fix agents, import graph, contract flows, memory JSON store, watchfiles watcher — all reused as building blocks.

**Changes:** Brain becomes layer-aware and incremental; a charter module is added; a reasoning/agent layer is added above the pipeline. No rewrite — everything is additive on the existing architecture.

---

## Key Decisions (locked for implementation)

1. **Charter input:** NL sentence (`p charter "..."`) parsed by LLM, stored as structured JSON, with manual-edit fallback.
2. **Layer summaries:** pure heuristic text now (fast, free); embeddings as a later opt-in.
3. **Build strategy:** **additive** — new `layered_brain.py` + `charter.py` wrap existing systems; zero breakage to the current pipeline.
