# Patchi — Orchestration Honesty & AI Harness Spec (Part 2)

Builds on `patchi-testing-security-moat-spec.md`. That doc was written from reading code.
This one is written from actually running the tool against a seeded test file
(one hardcoded API key, one textbook SQL injection via string concatenation, one
OS command injection via `os.system()`). Every bug below is a direct repro, not
a guess. Read this whole doc before starting — §1 is a structural fix that changes
where §2's bugs need to be fixed.

---

## 0. Non-Negotiable Rules (same as before, plus one)

1. Extend, don't rebuild. The Governor pipeline is good — it's just not wired in
   as the default, and it doesn't enforce its own gates yet.
2. No half-fixes.
3. Every "done" needs evidence, not a clean run.
4. **New: no flag-gated forks of core functionality.** §1 below exists because
   `p scan` currently has two entirely different implementations selected by a
   boolean flag, and the real one is undocumented. Don't solve today's problem by
   adding a third path — collapse it to one.

---

## 1. Merge the Governor Into Base `p scan` — Remove the Flag Entirely

### The exact problem, in code
`cli/commands/scan_cmd.py` currently forks on a `governor: bool = False` parameter:

- Line 344: `if not governor:` → runs a thin path that only dispatches
  `list_agents(AgentGroup.SCANNER)` — the ~9 generic code-quality scanners
  (EnvScanner, DependencyScanner, SPARouteInventoryAgent, etc.)
- Line 1102: `if governor:` → imports `Governor` from `core/agents/governor.py`
  and runs `gov.run_full_pipeline_v2()` — the real 7-phase pipeline that
  actually dispatches `AgentGroup.SECURITY` (all 125 security agents) as part
  of its SCAN phase.

**`--governor` does not appear in the README, `COMMANDS.md`, or `p scan --help`.**
This means: every documented, discoverable way to run Patchi (`p scan`, the
Quick Start commands, `p ready`'s default chain) runs the thin path and never
touches the security agents at all. I confirmed this directly — running `p scan`
and `p scan --deep --offline` against a file with an obvious SQL injection and
command injection produced zero findings for either. The only finding was a
hardcoded API key, caught by `EnvScanner`, which is in the thin `SCANNER` group,
not `SECURITY`.

### What to do
- Delete the `governor` parameter and both branches in `scan_cmd.py`. There is
  one `p scan` implementation, and it is what `run_full_pipeline_v2()` currently
  does — minus the honesty bugs fixed in §2 below.
- Brain's existing structural scan (file discovery → stack detection → source
  parsing → route mapping → import graph → contract inference — the 6/7 steps
  visible in current `p scan` output) becomes the implementation detail *inside*
  the Governor's `SCAN` phase, not a parallel thing `scan_cmd.py` calls directly.
  Confirm `Governor.run_scan()` already delegates to Brain for this (it should,
  per `core/brain/brain.py`'s role) — if it duplicates any of that logic instead
  of calling into Brain, that's a second thing to merge, not two working scanners.
- `AgentGroup.SECURITY` must be part of the default agent set dispatched by
  plain `p scan` — not opt-in, not behind any flag.
- Audit every doc/help string that references `--governor` or implies `p scan`
  and the "real" pipeline are different things (README, `COMMANDS.md`,
  `docs/patchi-testing-strategy-v2.md` where it discusses Governor as a v2
  add-on, `ROADMAP.md`) and update them to describe one pipeline.
- **Regression check**: after the merge, running plain `p scan` (no flags) against
  a file with `"SELECT * FROM users WHERE id = " + user_id` and
  `os.system("echo " + user_input)` must surface both as findings, not just a
  hardcoded secret. This is the actual acceptance test for this section — if it
  doesn't pass, the merge isn't done.

---

## 2. Fix the Governor's Honesty Bugs (now that it's the only path, it has to be trustworthy)

Running `run_full_pipeline_v2()` directly against the seeded test file surfaced
three separate ways the pipeline reports success when it shouldn't:

### 2a. "Pipeline PASSED" while its own log says findings remain
Actual log output from the run:
```
WARNING  governor:run_sandbox_reverify:1061 - Sandbox reverify: 112 findings remain after fix
INFO     governor:run_score_select:1139 -   CodeFixer: score=1.00 → auto_apply
INFO     governor:run_score_select:1139 -   SecurityFixer: score=1.00 → auto_apply
  ... (all 8 candidates scored 1.00 → auto_apply)
  Pipeline PASSED
```
Every fix candidate scored a perfect 1.00 and the pipeline reported PASSED in
the same run where it logged that 112 findings were still unresolved after the
fix. The scoring in `run_score_select` needs to factor in the sandbox reverify
result it already computed one step earlier — a candidate that leaves findings
unresolved cannot score 1.00, and a pipeline with unresolved post-fix findings
cannot report PASSED.

### 2b. Phase-order violations are logged, then ignored
```
WARNING  governor:_transition_to:433 - Invalid phase transition: graph_update → test_execution. Skipping ordering check.
```
The Governor detected its own phase sequence was invalid and then proceeded
anyway. If phase ordering matters enough to check, it matters enough to enforce.
`_transition_to` should either block the transition and surface a real error, or
the "invalid transition" case needs to be reclassified as valid (e.g. if skipping
TEST_GENERATION when there are no affected symbols is legitimately fine, that
should be a defined valid transition, not a caught invalid one that gets waved through).

### 2c. Swallowed finalization error
```
Governor.close checkpoint failed: database table is locked
```
This printed after "Pipeline PASSED" and nothing about the run's outcome
reflected that the close/checkpoint step actually failed. A failed persistence
step at the end of a pipeline run should not be invisible — at minimum surface
it as a warning attached to the run's result, ideally block re-declaring success
after it.

### 2d. "0 tests — 0 passed, 0 failed" renders as "All tests passed"
Separate from the Governor — plain `p test` against a project with no test files
produced:
```
Tests (UnitTest, Regression): 0 tests - 0 passed, 0 failed (6ms)
All tests passed.
```
This is the cleanest repro of the whole problem. Zero tests is not a pass. It
should report something like "No tests found" as a distinct state from "tests
ran and all passed" — and ideally this state should affect the health score /
readiness gate (an app with 0% real test coverage reporting the same success
banner as one with 100% passing coverage is a direct false-confidence signal to
whoever's reading it, human or agent).

---

## 3. Build the Actual AI Harness (once §1–2 mean the pipeline's verdicts can be trusted)

This is your "harness, not prompts" pivot — and it's not a new idea for this
project, it's already proven with real numbers in `docs/patchi-testing-strategy-v2.md`:
the same model given a raw whole-file prompt produced 11 tests with 9 hallucinated
failures; given a scoped harness (target symbol's signature + its real
call-graph neighborhood, nothing else) it produced 11 tests with 1 failure.
Same model. Only the harness changed.

Concretely, every AI-assisted step in the pipeline (test generation, fix
candidate generation, semantic classification) should go through:

1. **Scoped context builder, not raw file dumps.** Input to any AI call = the
   target symbol + its direct graph neighborhood (callers/callees), built from
   the SymbolGraph the merged `p scan` (§1) now maintains. Never whole-file or
   whole-repo context.
2. **Structured output contract, enforced.** Every AI call declares a schema for
   what it must return (e.g. a finding, a patch, a test). Parse and validate
   against that schema immediately — don't accept freeform text and regex it
   downstream.
3. **Reject-and-retry, not accept-and-hope.** If output fails schema validation
   or fails a determinism check (e.g. a generated test that doesn't actually
   compile/run), retry once with the specific failure fed back into the prompt,
   then escalate to human review — never silently accept a malformed result.
4. **This becomes measurable, not just designed.** Once `p eval` / the standing
   eval set from the previous spec's §5 exists, every harness change (prompt
   format, context scope, retry logic) gets run against it before shipping, and
   hallucination rate is tracked as a first-class number the same way test pass
   rate is.

---

## 4. Fix `p init`'s Non-Interactive Crash

Smaller, but real, and worth fixing early since an agent or CI running Patchi
non-interactively will hit this immediately:

```
Provider number or name (1): ... Paste your Groq API key   Paste your Groq API key: Traceback (most recent call last):
  File ".../cli/commands/init.py", line 371, in _secure_key_input
    return Prompt.ask(prompt)
EOFError: EOF when reading a line
```
- The crash happens because `Prompt.ask()` in `_secure_key_input`
  (`cli/commands/init.py:371`) has no handling for non-interactive stdin (EOF).
- **It also exits with code 0** despite the unhandled traceback — any script or
  agent checking the exit code will think init succeeded.
- Fix: catch `EOFError` explicitly, treat it as "skip AI setup for now" (project
  structure/`.patchi/` was already created successfully before this step — don't
  lose that), and exit non-zero only if something actually failed, not zero
  regardless of what happened.
- Add a real non-interactive path (`p init --no-logo` currently exists for CI but
  doesn't skip the AI provider prompt — it should, or a new flag should).

---

## Priority Order

1. **§1** — Merge Governor into base `p scan`, delete the flag. Nothing else
   matters if the security agents still don't run by default.
2. **§2** — Fix the three honesty bugs (score-vs-reverify mismatch, ignored
   phase violations, swallowed checkpoint error) plus the 0-tests banner.
   The merged pipeline from §1 has to be trustworthy the moment it becomes default.
3. **§4** — Fix the `p init` crash. Quick, and blocks any non-interactive/agent use.
4. **§3** — Build the scoped-context harness for AI calls, validated against the
   standing eval set from the previous spec.
