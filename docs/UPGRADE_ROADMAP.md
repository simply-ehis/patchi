# Patchi Upgrade Roadmap — Brain Smarts, Testing Depth, Context Layer

Written after reading all 8 specs in `files/`, verifying their execution status
against the current code, and sweeping the regex/heuristic surface
(see `docs/HEURISTIC_AUDIT.md`). Everything below is grounded in what exists
today — nothing requires a rebuild.

## 0. Spec execution status (verified this pass)

| Spec | Status |
|---|---|
| Part 1 (moat: eval set, gate calibration) | ✅ `evals/` + `p eval` live; 32-vs-74 honestly parked in `evals/pending/` |
| Part 2 (Governor merge, honesty bugs, AI harness) | ✅ merged; evidence gates in `PhaseCriteria`; `core/ai/harness.py` enforces schema + reject-retry |
| Part 3 (linking, tool registry, doctor --install) | ✅ `docs/LINKING_AUDIT.md` gate; unified tool health; auto-install + JSON |
| Part 4 (living knowledge doc) | ✅ `p docs` Tier 1 + drift checks; arch diagrams parity-gated |
| Part 5 (understanding quality) | ✅ `_derive_critical`, structural doc-claim verification, manifest-based purpose |
| Part 6 (zero-doc understanding) | ✅ docstring-first `_infer_purpose`, shared doc discovery, no-overwrite generation |
| Part 7 (heuristic annihilation) | ✅ this pass — `docs/HEURISTIC_AUDIT.md`; classifier KILL executed |
| Part 8 (SQLite concurrency) | ✅ `core/db.py` shared WAL+busy_timeout+retry |

## 1. Brain smarts — make understanding measurably better

### 1a. Confidence on every understanding claim (highest leverage)
Today `fi.purpose`, `ContractFlow.critical`, and project purpose carry no
confidence. Next step: give every Brain assertion a 0–1 confidence + the
evidence list that produced it (docstring found / AST import / manifest dep /
filename guess), and let consumers *threshold* instead of trusting. The
`(filename guess)` marker is the prototype — generalize it.

### 1b. Close the loop with runtime truth
`security_taint.py`'s route probing and `live_v2` both observe the real app.
Feed observed runtime behavior (real 401s, real route hits, real DB writes)
back into the Brain as the highest-confidence evidence tier — a route proven
alive at runtime outranks any static inference. This is Part 6 §2's "runtime
probing as comprehension evidence," still open.

### 1c. Symbol graph as the universal context provider
`build_symbol_context()` is harness-only today. Every AI call in the codebase
(`fix_agents`, `code_fixer`, doc narration, chat) should receive graph-scoped
context through it — one context builder, enforced at the call sites, so
"whole file in the prompt" becomes structurally impossible.

### 1d. Knowledge-doc section diffing as a decision log
Part 4 §4 (snapshots + architectural drift surfaced as findings) is the
highest-value remaining brain feature: it turns "the doc is current" into
"here is what changed architecturally since you last looked," derived from
real graph diffs, not commit messages.

### 1e. Test names as comprehension evidence
`test_checkout_fails_with_expired_card` is a sentence about the app that
breaks loudly when false. Parse test files' names + assertions into the
capability inventory — the cheapest untapped evidence source (Part 6 §2).

## 2. Testing depth — make `p test` prove things

### 2a. Done this pass
- **`p test live`** → `LiveTestRunnerV2Agent` (recordings + screenshots +
  visual regression + stress) is now reachable from the CLI with
  `record_video: True` — previously web-dashboard-only, the exact
  orphaned-feature pattern Part 3 killed elsewhere.
- **Evidence surfaced**: `_show_evidence()` names every screenshot/recording
  in `p test` results instead of burying them under `.patchi/`.
- **Harness-backed test generation** (`p test generate`): real behavioral
  pytest cases through `harness_call` — scoped symbol context, pydantic
  schema, reject-and-retry, and a semantic gate that rejects tests with no
  assert and tests that never import the code under test. The skeleton
  generator stays as the no-AI fallback.

### 2b. Next (in order)
1. **Mutation-gate the generated tests**: run `mutation_tester` on the files
   the harness generated tests for; a test suite that survives its mutants
   gets flagged at generation time (the anti-placeholder gate, extended from
   syntax to semantics).
2. **Screenshots as PR evidence**: `p test --out evidence.md` packaging
   screenshots + diffs + the impact diagram into one client-ready artifact
   (Part "professional tool" item 19).
3. **Coverage-guided generation targets**: `CoveragePrioritizerAgent` data
   (already collected in the Governor) should pick `p test generate`'s target
   files by *uncovered branches*, not file size.
4. **Flake history into eval**: `flake_detector` history feeds `p eval` so a
   test that flakes 30% shows up in the standing numbers, not just a warning.

## 3. Context layer — one ladder, everywhere

The evidence ladder should be explicit and uniform: **runtime observation >
AST/manifest fact > docstring > graph position > filename (marked guess)**.
Machine-readable per claim (1a), consumed by the AI harness (1c), verified
against the eval set (Part 1 §5), and rendered with sources in every report
(Part 1 §8). Every new feature should ask "which rung is this evidence on"
before it ships.
