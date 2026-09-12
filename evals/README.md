# Patchi standing eval set (spec §5)

Labeled cases the pipeline is scored against. Run with `p eval`.
Maintained like the test suite: every change to scanning, scoring, or
test/fix generation must keep `p eval` green before shipping.

## Layout
- `cases/gate_cases.json` — 16 labeled findings → expected `ConfidenceGate` routing
  (g01–g14 pin default behavior; g15–g16 pin knobs via per-case `gate_config`).
  Each expectation was hand-computed from `confidence_gate.py` + `ai_validator.py`
  (`heuristic_pre_filter`). If the gate logic changes, update the expectation
  *with the numbers on the table*, never to make the run green.
- `cases/noise_cases.json` — 10 path/mode → kept|capped|discarded expectations
  (n09–n10 pin toggles via per-case `filter_config`).
- `kind` is `vuln` | `clean` | `config`: `config` cases pin a knob and count
  only toward routing accuracy (excluded from vuln-recall / escape invariants).
- `pending/` — disputes that cannot be scored yet (missing ground truth).

## Metrics (`p eval`)
- **routing accuracy** — exact routing match / total (gate).
- **vuln recall** — vuln cases routed anywhere except `discard` (a vuln must never be dropped silently).
- **clean defend escapes** — clean cases routed `defend` (must be 0; traps may sit in ai_analyze/human_review, never auto-defend).
- **noise accuracy** — exact kept|capped|discarded match / total (noise).

## Generation eval
- `cases/generation_cases.json` — 3 seeded vulns; the model must generate a
  regression test that references the seeded symbol and parses as Python.
- `p eval` stays offline (SKIPPED by design). `p eval gen` / `p eval --gen`
  opts in (spends tokens): grounded vs hallucinated per case, rate recorded
  per model + `GEN_PROMPT_VERSION`.
- A skip is never a pass: `ok` is `None` when skipped, `FAIL` overall when a
  requested measurement can't run. (Spec rule 3: a clean run with no
  assertions is "partial" at best.)
