# Patchi — Testing & Security Moat Hardening Spec

Written after cloning and reading the actual repo (`simply-ehis/patchi`), not from
guesswork. This references real files, real logic, and one concrete documented
gap the project's own history already flagged. Read `docs/patchi-testing-strategy-v2.md`,
`AGENT_FEEDBACK.md`, and `core/agents/governor.py` before starting — this spec builds
directly on them.

---

## 0. Context — What's Actually Here (so nothing gets rebuilt by accident)

This is not a small project. It already has:
- A risk-gated fix pipeline (`core/fix/risk_gate.py`) — ALLOW_AUTO / REQUIRE_REVIEW / BLOCK
- A scored confidence system for findings (`core/security/confidence_gate.py`) — HIGH/MEDIUM/LOW tiers,
  false-positive memory, multi-agent confirmation bonuses
- A noise filter for known-noisy file types (`core/security/noise_filter.py`)
- A "is the app even runnable" gate (`core/testing/gate.py` + `cli/commands/check_cmd.py::is_ready`)
  that's supposed to block Testing/Security agents until `READY_TO_SERVE`
- A 7-phase Governor state machine (`core/agents/governor.py`, ~2000 lines) implementing
  a documented v2 architecture: `SCAN → GRAPH_UPDATE → TEST_GENERATION → TEST_EXECUTION →
  FIX_GENERATION → SANDBOX_REVERIFY → SCORE_SELECT`
- A design doc (`docs/patchi-testing-strategy-v2.md`) that **already correctly diagnoses**
  the overconfidence problem and proposes the fix (graph-scoped context to cut hallucination,
  a Not-Done/Partial/Done acceptance table per phase, a standing eval set)

**This means the "moat" isn't something to invent — it's something to finish enforcing.**
The architecture for honesty already exists on paper. The gap is that the code doesn't
yet hold itself to it.

---

## 1. Non-Negotiable Rules

1. **Extend, don't rebuild.** `governor.py`, `confidence_gate.py`, `risk_gate.py`, and
   `noise_filter.py` are solid foundations — build on them. Do not create a parallel
   "v3" system next to them.
2. **No half-fixes.** If tightening a gate in one agent means another agent now needs
   updating to match, do both in the same pass.
3. **Every "done" needs evidence, not a clean run.** Per the project's own testing
   strategy doc: *"a clean run with no assertions behind it is 'partial' at best."*
   Apply this rule to every phase, not just the ones already called out.
4. **Don't let a known discrepancy sit open.** See §3 — there's already a documented,
   unresolved accuracy gap in the repo's own history. Close it before adding new checks.

---

## 2. The Actual Root Cause of "Overconfidence" (found in code, not assumed)

`core/agents/governor.py` implements phase transitions gated by `PhaseCriteria`
(`_check_criteria`, around line 400). Look at what it actually checks:

```python
class PhaseCriteria:
    max_errors: int = 0
    max_critical_findings: int = 0
    max_high_findings: int = 10
    min_agents_run: int = 1
    require_zero_errors: bool = True
```

A phase currently "passes" if: not too many agent crashes, and not too many findings
above a count threshold (some phases allow up to **200 critical / 1000 high** findings
and still pass). That's a crash detector and a volume cap — it is not a correctness
check. A phase can transition to "done" while having generated hallucinated tests,
skipped real vulnerability classes, or verified nothing at all, as long as nothing
*crashed* and the finding count stayed under the cap.

Compare this to what the project's own `docs/patchi-testing-strategy-v2.md` (§3a)
already specifies as the bar for "done" per phase — e.g. for test generation:
> *"Run against the standing eval set, hallucination rate measured and recorded
> per model/prompt version, result compared against the 11-vs-1 baseline."*

**That richer acceptance table exists only in the doc. `_check_criteria` in code
implements a much thinner version of it.** This gap — rigorous acceptance criteria
designed but not enforced — is the concrete mechanism behind "overconfident."

### The fix
Rewrite `PhaseCriteria` / `_check_criteria` in `governor.py` to actually implement
the §3a "Done" column per phase, not just error/finding counts:
- **SCAN**: findings normalized into the shared schema, mapped to a `technique_id`/`control_id`,
  and validated against known-seeded issues (true-positive rate + false-positive rate recorded,
  not assumed).
- **TEST_GENERATION**: run against the standing eval set (build this — see §5), hallucination
  rate measured and stored per model/prompt version.
- **TEST_EXECUTION**: a failing test must hard-block progression to FIX_GENERATION —
  confirm this is actually enforced, not advisory.
- **FIX_GENERATION**: multiple candidates scored on the full composite (tests pass +
  mutation subset + blast-radius delta + no new scan findings), with every candidate's
  score logged — not just the winner's.
- **SANDBOX_REVERIFY**: the *same* scoped test set from TEST_EXECUTION re-run verbatim
  in an isolated checkout, plus the loop-back scan re-run on the diff. If it's a
  different or smaller test set than step 4 used, that's "partial," not "done" — flag it.
- **SCORE_SELECT**: auto-apply only for domains explicitly marked autonomous in the
  criticality taxonomy; verify with at least one seeded high-criticality case that
  correctly escalates instead of auto-applying.

Every phase result should carry an **evidence field**, not just a pass/fail verdict —
what was actually checked, against what baseline, with what measured rate. If a phase
can't produce evidence, it doesn't get to report "done."

---

## 3. Close the Open Accuracy Gap (don't add new checks on top of an unresolved one)

`AGENT_FEEDBACK.md` already documents this, unresolved:

> *"DuplicateScanner still 5704 after noise filter — correctly discarded via NoiseFilter
> + ConfidenceGate low tier discard to reach 32 real; user reported 74 real, our gate
> kept 29 medium + 3 high = 32 close — may need threshold tuning if 74 is ground truth."*

This is a live, admitted instance of the exact problem you're describing: the gate's
output (32) doesn't match the human's ground truth (74), and the note ends in "may
need tuning" — i.e. nobody confirmed which number is right.

**Before building new confidence/gating logic, resolve this one:**
1. Get the ground-truth 74 findings (or re-derive them) and diff against what
   `ConfidenceGate` currently keeps.
2. Determine whether the gap is in `noise_filter.py` (over-discarding), `confidence_gate.py`
   thresholds (`min_agents_for_defend`, `fp_penalty`, `ai_weight` — all in the config),
   or `DuplicateScanner` itself under-detecting.
3. Whatever the fix, add the 74-vs-32 case as a permanent regression case in the eval
   set from §5 so this can't silently regress again.

---

## 4. Confidence Gate — Prove the Thresholds, Don't Just Trust Them

`core/security/confidence_gate.py` is well-designed (method precision, severity bonus,
multi-agent confirmation, false-positive memory) but the actual numeric thresholds
(HIGH ≥ 0.7, MEDIUM ≥ 0.4, `fp_penalty=0.3`, `ai_weight=0.3`) appear to be reasonable
defaults, not thresholds validated against real data. This is the second half of
"overconfident" — a well-structured scoring system with unverified calibration.

- Build a labeled validation set (seeded true positives + seeded known false positives
  across the main finding types) and run the gate against it.
- Report precision/recall per tier, not just "gate ran."
- Tune thresholds against that measurement, and re-run it as a regression check on
  every change to `confidence_gate.py` — same discipline as §3's eval set.

---

## 5. Build the Standing Eval Set (referenced everywhere, doesn't exist yet)

Both `docs/patchi-testing-strategy-v2.md` (§4) and the fix above depend on this:
> *"Maintain a routing/generation eval set the same way a test suite is maintained...
> Run it against every prompt-format or context-scoping change before shipping."*

This needs to actually be built:
- A directory of labeled cases: known-seeded vulnerabilities (true positives), known
  clean code that looks suspicious (false-positive traps — test fixtures, migration
  SQL, minified bundles), and known-correct fix outcomes.
- A runnable command (`p eval` or similar) that scores current agent output against
  it and reports hallucination rate, false-positive rate, and detection rate as
  first-class numbers — not buried in logs.
- This becomes the actual regression gate for every future change to scanning,
  scoring, or test/fix generation. Nothing in §2–4 is real without this existing.

---

## 6. Close the Testing-Depth Gaps That Directly Cause False Confidence

`ROADMAP.md` §1 lists these as still missing from the Testing section — they're not
cosmetic, they're exactly what prevents false "all good" reports:

- **Flaky test detection** — a "passing" test suite that's actually flaky is a
  confidence lie. `core/testing/flake_detector_agent.py` exists; confirm it's wired
  into the Governor's TEST_EXECUTION phase and actually gates on flake rate, not
  just reported separately.
- **Mutation testing** — the only way to know tests actually catch bugs (vs. just
  running without asserting anything meaningful). This is explicitly required by
  §2 of the acceptance criteria for FIX_GENERATION scoring in the strategy doc.
- **Coverage-guided prioritization** — without this, "we ran tests" doesn't mean
  "we tested the part that changed."
- **Contract test generation** — API/schema drift is a classic "everything looks
  fine until a client breaks" overconfidence trap.

---

## 7. Harden the Bare-Minimum Gate (this is the prerequisite, not part of the moat itself)

You're right that before Testing/Security can be smart, the app under test needs to
just *work*. This gate already exists conceptually:

- `core/testing/gate.py::require_ready()` checks `is_ready()` from `check_cmd.py`
- `is_ready()` requires `status == READY_TO_SERVE` and a reachable `url`
- The restructuring plan's `p ready` command is meant to chain: Testing → Code
  Structure → Integration → Performance → Security Basics → Visual, in that order

This is the right shape — it just needs to be bulletproof, since every other gate
in §2–6 depends on this one being trustworthy first:
- Confirm `is_ready()` actually re-validates the URL is reachable at check time
  (the code has a comment `# check url still reachable?` that was never implemented —
  that's a gap, fix it).
- Confirm no Testing or Security agent can bypass `require_ready()` — audit for any
  agent that doesn't call the gate check before running.
- `p scan` and `p ready` should fail loud and specific ("build failed: X", "app didn't
  bind to port Y") rather than silently reporting incomplete results as if they were complete.

---

## 8. Reporting Honesty

Whatever comes out of the web UI / CLI report needs to show its work:
- Every finding shows which tier it passed through (`ConfidenceGate` tier) and why.
- Every "phase passed" shows the evidence that justified it (per §2), not just a green check.
- Distinguish, visibly, between "agent ran and found nothing" and "agent ran, was
  validated against the eval set, and found nothing" — these are very different
  claims and currently look identical in a report.

---

## Priority Order

1. **§3** — Resolve the open 32-vs-74 discrepancy first. Don't build new trust
   mechanisms on top of an admitted unresolved accuracy gap.
2. **§7** — Harden the bare-minimum readiness gate. Everything else assumes it's solid.
3. **§5** — Build the standing eval set. Nothing else can be *proven* fixed without it.
4. **§2** — Rewrite Governor phase acceptance criteria to be evidence-based.
5. **§4** — Validate and tune confidence gate thresholds against the eval set.
6. **§6** — Close the testing-depth gaps (flaky detection wiring, mutation testing,
   coverage-guided prioritization, contract tests).
7. **§8** — Make reports show evidence, not just verdicts.
