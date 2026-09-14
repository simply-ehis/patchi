# Patchi — Testing Strategy v2
### Scan-Before-Fix Ordering, Graph-Scoped Test Generation & the Governor Architecture
Draft v0.1

---

## 0. What Changed From v1

The original testing plan (10 tool-wrapping agents, exploration/mapping agent as shared graph) is still the foundation. Two things sharpened since then, both validated by direct evidence rather than theory:

1. **Ordering matters.** Scan, test, and fix aren't parallel/interchangeable phases — they have a real dependency chain, and skipping the order produces untrustworthy fixes.
2. **Graph-scoped context beats huge-context for AI test generation, measurably.** A raw full-context test generator produced 11 tests with 9 hallucinated failures. The same task, given only the target symbol's signature plus a graph-derived summary of its actual dependencies, produced 11 tests with 1 failure. Same model, same task — the only variable was how the input was scoped. This isn't a token-cost optimization, it's a hallucination-reduction mechanism, and it reframes how every AI-assisted step in the pipeline should be built.

A third decision closes out the architecture question that came out of this: **the "brain" stays fully deterministic orchestration logic — no LLM (tiny or large) sits at the center making routing decisions.** Reasoning below.

---

## 1. Why a Tiny LM as the Central Brain Was Rejected

The idea (a small local model — Liquid LM2.5 class, 350M–730M params — reading everything and routing to the right agent) was worth evaluating seriously, and it's worth recording *why* it was scratched, so the reasoning doesn't need re-litigating later:

- **Unpredictability compounds at the center of a system.** A misrouted scan finding or misrouted test result doesn't fail loudly — it silently sends work to the wrong specialist, or drops it. At the edges (one agent's output), a bad call is contained. At the center (every signal passes through it), a bad call is systemic.
- **It would need its own enormous rulebook to be reliable** — effectively rebuilding all the deterministic routing logic anyway, just behind a layer of model unpredictability instead of in front of it. That's strictly worse: same engineering cost, less auditability.
- **Small models are worse at graceful uncertainty**, not better — they're more likely to confidently misclassify an edge case than a larger model, and a router is *made of* edge cases by definition (that's what "ambiguous signal" means).

The correct role for any LLM, tiny or large, in this system stays what it was already trending toward: **a narrowly-scoped tool called by deterministic logic for one bounded task, never the thing making the routing decision itself.**

---

## 2. The Governor / Worker-Ants Architecture

This replaces "brain routes everything" with "brain aggregates and plans, ants execute narrow jobs, findings flow back structured." As of the §1 merge, the Governor is not an opt-in v2 add-on — it IS the `p scan` pipeline: the Brain's structural pass is the implementation detail inside the Governor's SCAN phase, the SECURITY agent group dispatches by default, and there is no separate thin scan path.

```
                         ┌──────────────────────────┐
                         │        GOVERNOR           │
                         │  (deterministic logic —   │
                         │  receives all structured   │
                         │  findings, plans pipeline, │
                         │  dispatches work, never    │
                         │  reasons freeform)         │
                         └────────────┬──────────────┘
                                      │  dispatch
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
       ┌────────────┐         ┌────────────┐          ┌────────────┐
       │  WORKER ANT │         │ WORKER ANT │          │ WORKER ANT │
       │ (scan tool, │         │ (test agent,│          │ (fix       │
       │  e.g. Gitleaks)       │  e.g.       │          │  candidate │
       │             │         │  Playwright)│          │  generator)│
       └─────┬───────┘         └─────┬──────┘          └─────┬──────┘
             │  structured finding    │                       │
             └────────────────────────┴───────────────────────┘
                                      ▼
                         back to GOVERNOR (aggregate, replan)
```

**Governor responsibilities (all deterministic):**
- Owns the pipeline state machine (scan → test → fix → reverify → done, per Section 3).
- Receives every worker ant's output in one **structured finding format** (not freeform text) — same discipline as the event envelope from the detector design.
- Decides next dispatch based on rules over that structured data: severity, domain activation state, blast-radius weight, confidence — the same taxonomy/scoring logic already specified, not new logic.
- Owns the audit log. Every dispatch and every finding is logged with enough context to reconstruct why the governor made that call.
- Handles the "ambiguous" bucket not with a model, but with an explicit escalation rule: unresolved-confidence findings get flagged for human review, full stop. No model guesses on the governor's behalf.

**Worker ants:**
- Each is a narrow, replaceable unit — a tool wrapper or a scoped LLM call. Ants don't talk to each other directly and don't make pipeline decisions — they do one job and report back in the shared structured format.
- Ants can be added/removed/upgraded independently as long as they honor the finding schema — this is what keeps the system extensible without touching the governor's logic.
- **No ant ships as a bare wrapper stub.** "Integrated" means: tool installed/vendored, invoked with real config against a real target, output parsed into the structured finding schema (Section 7), and passing its acceptance check (Section 8) — not "the CLI command runs and prints something."

---

## 2a. Worker Ant Registry — Named Tools, Not Categories

This is the buildable inventory. Every row is a checklist line: **Built from scratch** (Patchi-original logic, no external tool) vs. **Wraps OSS tool** (integration work, not reimplementation) vs. **Mixed**.

| Ant role | Tool(s) used | Build type | What "wraps" actually means here |
|---|---|---|---|
| Exploration/mapping — static | ts-morph (TS/JS), `ast`+`jedi` (Python), Tree-sitter (fallback) | Wraps OSS libs, orchestration is original | Parse AST, extract symbols/edges, write to graph store — the graph schema/store itself is original |
| Exploration/mapping — dynamic crawl | Playwright | Wraps OSS tool | Headless crawl script + state-dedup logic (original) sits on top of Playwright's browser automation |
| Flow/journey testing | Playwright | Wraps OSS tool | Test *execution* engine is Playwright; the graph-driven journey selection logic is original |
| Visual regression | BackstopJS or reg-suit | Wraps OSS tool | Screenshot diffing engine is the tool; route list fed in comes from the graph |
| Load/stress testing | k6 and/or Locust | Wraps OSS tool | Load generation is the tool; scoping which endpoints to hit (blast-radius-derived) is original |
| Contract/API testing | Schema diffing against OpenAPI/GraphQL SDL — `oasdiff` (OpenAPI), `graphql-inspector` (GraphQL) | Wraps OSS tool | Diff engine is the tool; deciding which schema changes are breaking vs. safe is original policy logic |
| Fuzzing | AFL++ / libFuzzer (native), Atheris (Python), Jazzer (JVM/Kotlin) | Wraps OSS tool | Fuzzing engines are the tools; target/harness selection scoped to parser/input-boundary functions is original |
| Accessibility | axe-core (via `@axe-core/playwright`) or Pa11y | Wraps OSS tool | Direct library integration, minimal original logic — this is the ant that should be near-100% built, not partial |
| Chaos/fault injection | Toxiproxy (network-level) or Chaos Mesh (k8s-level, standalone/hosted mode only) | Wraps OSS tool | Fault injection engine is the tool; which flows to target is graph-derived |
| Mutation testing | Stryker (JS/TS), mutmut (Python) | Wraps OSS tool | Mutation engine is the tool; "which files to mutate" scoping to the diff is original |
| Property-based testing | fast-check (JS/TS), Hypothesis (Python) | Wraps OSS tool | Generation engine is the tool; invariant definitions per function are original (or LLM-assisted, narrow scope) |
| Combinatorial/pairwise testing | PICT (Microsoft, open source) | Wraps OSS tool | Pairwise-set generation is the tool; mapping app config/flags into PICT's input model is original |
| Static security scan | Semgrep (SAST), CodeQL (dataflow/taint) | Wraps OSS tool | Rule execution is the tool; rule selection tied to the domain taxonomy is original |
| Dependency/SCA scan | OSV-Scanner, Trivy, Grype | Wraps OSS tool | Scan engine is the tool; result normalization into the finding schema is original |
| Secrets scan | Gitleaks, TruffleHog | Wraps OSS tool | Same pattern as above |
| DAST | OWASP ZAP, Nuclei | Wraps OSS tool | Attack templates are the tool; this ant doubles as an attack-sim source per the earlier plan |
| Test generation (AI-assisted) | LLM call + graph-neighborhood context builder | **Built from scratch** | The context-scoping logic (Section 4) IS the differentiator — no OSS tool does graph-scoped test generation; this is original engineering, not a wrapper |
| Fix candidate generation (AI-assisted) | LLM call + graph-neighborhood context + deterministic autofix layer (ESLint `--fix`, Semgrep autofix, jscodeshift codemods, `npm audit fix`) | **Mixed** | Deterministic layer wraps OSS tools; LLM fallback + candidate scoring + deterministic-first ordering is original design |
| Semantic mismatch classifier | Narrow LLM call, no OSS equivalent | **Built from scratch** | Purpose-built classifier prompt/contract, not a wrapped tool |
| Dangling/orphan edge detection | Graph traversal over the mapping agent's own store | **Built from scratch** | Pure graph math, no external tool needed — should be one of the fastest ants to fully complete |
| Attack simulation | Atomic Red Team, Caldera (MITRE), Stratus Red Team | Wraps OSS tool | Test-firing harness is original; the attack technique library is the tool |

If a checklist tool is auto-generating build status from these docs, the **"Build type" column is the field to key off** — anything marked "Wraps OSS tool" isn't done until the tool is actually vendored/installed and passing real output through the finding schema, not just imported. Anything marked "Built from scratch" has no shortcut — there's no library to install that makes it appear partially done.

This is the same shape as a build system's scheduler (Bazel, Nx) dispatching independent, narrowly-scoped jobs and aggregating results deterministically — not a coincidence, it's the correct pattern for exactly this problem, and it's why earlier sections of the master plan already leaned this way without naming it explicitly.

---

## 3. Pipeline Ordering: Scan → Test → Fix

The dependency chain, and why the order isn't arbitrary:

```
1. SCAN (structural pass)
   → static rule violations, dangling graph edges, dependency CVEs, secrets
   → updates the symbol-level graph

2. GRAPH UPDATE
   → incremental patch (Section 4 of the mapping agent spec), not full rebuild

3. TEST GENERATION — graph-scoped
   → scoped to symbols the diff/scan touched, using neighborhood summaries
     (signature + direct callers/callees), NOT whole-file or whole-repo context

4. TEST EXECUTION
   → structural, dynamic, and targeted tiers all run here (per prior testing plan)
   → results become the oracle fix verification will check against

5. FIX CANDIDATE GENERATION
   → deterministic autofix first; LLM candidates only for residual cases
   → candidates scoped to graph neighborhood, same discipline as step 3

6. SANDBOX REVERIFICATION
   → re-run the SAME scoped test set from step 4 against each candidate
   → also re-run step 1's scan on the candidate diff (catch new findings the fix introduced)

7. COMPOSITE SCORE → SELECT OR ESCALATE
   → passes all gates → apply (if domain risk allows autonomy)
   → fails or ambiguous → escalate to human, with full evidence trail
```

**Why scan must run before test generation:** scan produces the up-to-date graph state that test generation depends on for scoping. Generating tests against a stale graph reintroduces the exact hallucination risk the graph-scoping fix was built to solve — the 9-failure result happened *because* the model didn't have accurate structural grounding, and a stale graph is functionally the same failure mode as no graph.

**Why test execution must complete before fix verification is trustworthy:** a fix can't be honestly scored as "safe" against a test set that hasn't been scoped and run yet. Scoring a fix against an empty or incomplete test set produces false confidence — worse than not scoring it at all, since it looks verified but isn't.

**Why the loop-back scan in step 6 matters:** a fix can pass every functional test and still introduce a new lint violation, a new secret, a new dangling route. Step 6 isn't optional cleanup, it's closing the same loop step 1 opened.

---

## 3a. Acceptance Criteria Per Phase — What "Done" Actually Requires

Without this, a checklist consumer has no way to distinguish "the pipeline ran once and nothing crashed" from "the pipeline is validated." Each phase below needs its stated evidence before it can be marked complete — not partial, not "implemented," complete.

| Phase | Not done | Partial | Done |
|---|---|---|---|
| **1. Scan** | Ant wrapper exists, not run against a real target | Runs against Juice Shop/DVWA but findings aren't normalized into the shared schema | Runs against a real target repo, findings normalized, mapped to a `technique_id` or `control_id`, and manually verified against at least 3 known-seeded issues (true positives confirmed, false positive rate recorded) |
| **2. Graph update** | Static extractor produces a graph once | Full graph builds, but re-running on a diff triggers a full rebuild, not a patch | Incremental patch confirmed: changing one file updates only affected nodes/edges, verified by timing (patch << full rebuild) and by diffing graph state before/after against expected output |
| **3. Test generation (graph-scoped)** | LLM call exists, context is whole-file or whole-repo | Graph-scoped context wired in, but no eval set — "seems to work" | Run against the standing eval set (Section 4), hallucination rate measured and recorded per model/prompt version, result compared against the 11-vs-1 baseline |
| **4. Test execution** | Tests generated but not actually run | Tests run, but results aren't fed back into the finding schema for the governor to consume | Test run results structured and consumable by the governor; a failing test blocks progression to fix generation (this gate is enforced, not advisory) |
| **5. Fix candidate generation** | LLM produces a diff, applied directly with no verification | Candidates generated, but only one candidate tried, no scoring | Multiple candidates generated, scored against the full composite (tests pass, mutation subset, blast-radius delta, no new scan findings), and the scoring decision is logged with all candidate scores — not just the winner |
| **6. Sandbox reverification** | Fix applied directly to the working tree | Fix tested in a sandbox, but against a different/smaller test set than step 4 used | Same scoped test set from step 4 re-run verbatim against the candidate in an isolated checkout/container, plus the loop-back scan from step 1 re-run on the diff |
| **7. Selection/escalation** | Any passing candidate auto-applies regardless of domain | Autonomy gating exists but isn't tied to the domain-criticality taxonomy | Auto-apply only for domains/criticality levels explicitly marked autonomous in the taxonomy; everything else routes to human review with the full evidence trail attached, verified with at least one seeded high-criticality case that correctly escalates instead of auto-applying |

**General rule for the checklist parser:** a phase is not "done" without a recorded test case (seeded issue, known-answer eval, or explicit before/after measurement) proving it behaves as specified — a clean run with no assertions behind it is "partial" at best.

---

## 4. Graph-Scoped Generation as a Standing Discipline

The 11-vs-1 result should be treated as the first data point in a permanent internal benchmark, not a one-off comparison. Concretely:

- **Every AI-assisted step in the pipeline** (test generation, fix candidate generation, semantic-mismatch classification from the silent-bugs discussion) gets built on the same contract: input = target symbol + direct graph neighborhood summary, never raw whole-file or whole-repo context.
- **Maintain a routing/generation eval set** the same way a test suite is maintained: labeled cases of "given this scoped context, the correct test/fix/classification is X." Run it against every prompt-format or context-scoping change before shipping that change. This is what turns the 11-vs-1 anecdote into an actual regression gate.
- **Track hallucination rate as a first-class metric**, alongside detection rate and false-positive rate from the attack-simulation framework — this is the same discipline applied to the AI-assisted steps that Section 4 of the earlier attack-sim plan applies to the detector.

---

## 5. Where This Leaves Silent/Semantic Bugs

Consistent with the earlier discussion — this pipeline doesn't manufacture ground truth where none exists, but the governor/ant structure makes the honest version of it dispatchable, cleanly:

- **Dangling/orphan route detection** — a scan-tier worker ant, pure graph traversal, no LLM. Runs in step 1.
- **Regression-diff detection** (label→destination baseline drift) — a scan-tier worker ant comparing current crawl graph to prior snapshot. Also step 1, also no LLM required to detect, though flagged findings may get an LLM-based semantic-plausibility second opinion as a narrow step 3-adjacent ant.
- **Semantic mismatch flagging** — a dedicated worker ant whose entire job is the narrow classifier call from the earlier discussion ("does label X plausibly match destination Y"), returning a structured finding with confidence — never a fix, never auto-applied, always routed by the governor to human review per the domain-risk gating rule already established.

This keeps the "we can't know ground truth" limitation honest and contained to one clearly-scoped ant, instead of leaking uncertainty into the rest of the deterministic pipeline.

---

## 6. Summary of the New Shape

| Old framing | New framing |
|---|---|
| 10 agents wrapping individual tools | Roles (explore, flow, load, contract, fuzz, fix-verify) each capable of calling multiple tools |
| Tiny LM as central brain routing everything | Deterministic governor; LLMs only as narrow worker ants |
| Fix pipeline calls LLM with file + instruction | Fix pipeline scopes LLM calls to graph neighborhood, deterministic autofix first, LLM as fallback |
| Test generation from whole-file/whole-repo context | Test generation scoped to symbol + graph-derived neighborhood summary |
| Scan/test/fix treated as loosely ordered phases | Explicit dependency chain: scan → graph update → scoped test gen → test exec → fix gen → sandbox reverify → loop-back scan |
| No formal way to know if a change helped | Standing eval set + hallucination-rate tracking as a first-class pipeline metric |

---

*This document supersedes the agent-role breakdown in the prior testing discussion where they conflict, and is a child document of the Patchi Master Plan. It assumes the Exploration/Mapping Agent spec's graph schema and incremental-update model as a dependency. Section 2a (tool registry) and Section 3a (acceptance criteria) exist specifically so build-tracking tools parsing this document can distinguish "tool named and integrated" from "concept described," and "phase validated with evidence" from "phase ran once" — treat both sections as required reading before marking any line item complete.*
