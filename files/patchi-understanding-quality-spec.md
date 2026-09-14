# Patchi — Understanding Quality Spec (Part 5)

Every finding in this doc is verified against actual code, not inferred. This is
a prerequisite for Part 4 (the living knowledge doc) — that spec assumes
`contract.py` produces a trustworthy "what's critical and why" list and that
`doc_validator.py` produces trustworthy doc-coverage data. Right now neither is
true. Fix these first, or the knowledge doc in Part 4 inherits the same false
confidence everything else in this project has had.

---

## 0. Non-Negotiable Rules (same as prior specs)

1. Extend, don't rebuild — `blast_radius.py`, `freshness.py`, and the existing
   claim-extraction pipeline are the right foundations, just disconnected.
2. No half-fixes.
3. Every claim needs evidence — this whole spec is about enforcing that rule
   on the modules whose entire job is producing "understanding."
4. No silent skips reported the same as "nothing to report" — this spec's
   central theme, applied to two more modules.

---

## 1. Make "Critical" Mean Breakage Risk, Not "A Flow Was Detected"

### The exact problem
`core/brain/contract.py`:
```python
@dataclass
class ContractFlow:
    ...
    critical: bool = True
```
This is never computed anywhere in the file's 889 lines. Every flow from every
inference path (`infer()`, `project_infer()`, the AI summariser) ends up
`critical=True` by default. There is currently no distinction in this system
between "this is your auth flow" and "this is a settings toggle."

### What to do
Replace the static default with a computed score, using data that already
exists:
- **Blast radius** (`core/brain/blast_radius.py`) — already computes a
  `risk_level: low/medium/high` per file/symbol, weighted by test coverage and
  fan-in from the reverse dependency graph. This is the actual "where will it
  break, and how far does the damage spread" signal. Wire it directly into
  `ContractFlow` construction — a flow's criticality should be derived from the
  blast radius of the files/routes it covers, not asserted.
- **Test coverage gap** — a flow whose files have no test coverage is higher
  risk than one that's well-tested, independent of how "important" it sounds.
- **External-facing surface** — routes that accept user input, touch auth, or
  write data are inherently higher-risk than read-only internal ones; this is
  cheap to detect from the route method/path/handler shape already parsed.
- **Historical fragility** — if `trend_cmd.py`'s history tracking shows a
  file/flow has produced findings or been touched by fixes repeatedly, that's
  a real fragility signal, not a guess.
- Combine these into an actual score (not just true/false) so the contract can
  rank flows by real risk, and surface *why* a flow is critical (e.g. "high
  blast radius, 0% test coverage, handles auth") — not just a flag.

### Acceptance check
Take two flows in a real project — one with high fan-in and no tests, one with
low fan-in and full coverage — and confirm the contract ranks them differently.
If both still come out identically "critical: true," this isn't done.

---

## 2. Fix the Doc Validator's Silent-Skip and Weak Verification

### 2a. Silent skip
`cli/commands/scan_cmd.py`:
```python
dv = report.doc_validation or {}
if dv.get("total_claims", 0) > 0:
    ...
```
When `total_claims == 0` — which happens whenever the regex patterns in
`doc_validator.py` don't happen to match the project's README phrasing, or
there's no README at all — nothing prints. No "no claims found," no "docs too
sparse to validate," nothing. The feature silently does nothing and looks
identical to "ran and found no issues." Fix: always print a result line,
including the zero case, with a real reason (no doc files found / doc files
found but no extractable claims / N claims checked).

### 2b. Weak verification
`core/brain/doc_validator.py`:
```python
verified = len(evidence) >= 1
```
A single overlapping token anywhere in the entire codebase's vocabulary counts
as "verified." This needs a real bar — require multiple distinct token matches
concentrated in one place (not scattered across five unrelated files), or route
uncertain claims through a scoped AI check the way Part 2 §3 specifies for
everything else: hand the AI the claim plus the actual candidate evidence
file(s), ask it to confirm the claim is actually substantiated (not just
lexically adjacent), and require a `file:line` citation back. Bag-of-words
overlap is a heuristic prefilter at best, not a verification method.

---

## 3. Close the Blind Spot — Discover Capabilities From Code, Not Just From Docs

This is the structural gap, not a bug fix. Every existing path (`doc_validator.py`'s
regex extraction, `DocClaimAgent`'s LLM extraction) starts from parsing
documentation for claims. Neither can ever detect a real, working feature that
nobody wrote a doc line about — there's no reverse direction.

### What to build
- A **capability inventory built directly from code**, independent of any doc:
  every route (`route_mapper.py`), every CLI command (the command registry),
  every public class/function Brain's AST parsing already extracts, every
  registered agent's stated purpose. This is pure Tier-1 rendering, same
  principle as Part 4 §1 — no AI needed, just enumeration of what already
  exists in the graph.
- **Diff that inventory against what the docs actually mention.** Anything in
  the code-derived list with no corresponding doc claim becomes a new finding
  category: "undocumented capability" — symmetric to "stale claim" (docs
  mention something code doesn't have) but the mirror case (code has something
  docs don't mention).
- **Reuse this same inventory in Part 4's knowledge doc.** Don't build this
  twice — the knowledge doc's "what can this app do" section and this
  gap-detection check should read from the same code-derived capability list.
  This is the same kind of avoidable duplication flagged in Part 3 — build it
  once, wire both consumers to it.

### Acceptance check
Add a real, working route or CLI command to a test project with zero mention
in any doc file. Confirm the scan reports it as an undocumented capability. If
it's invisible, this section isn't done.

---

## 4. Stop Locking the Contract Permanently on First Form

### The exact problem
`core/brain/brain.py`:
```python
if inferred and not brain_mem.get("contract_locked"):
    ...
    brain_mem["contract_locked"] = True
    brain_mem["contract_auto_formed"] = True
```
Once set, nothing anywhere unlocks or re-evaluates this. If the first scan that
ever forms a contract happens before AI is configured (a very plausible
first-run case), the contract is permanently built from the weakest inference
path — pattern matching against `_ROUTE_TO_FLOW`, a table whose entries
(`hosted`, `brain`, `agents`, `keys`, `queue`) read like they were seeded from
Patchi's own dashboard, not generalized for arbitrary target projects. A
generic `/keys` or `/queue` route on someone else's app risks being confidently
mislabeled with Patchi-specific meaning.

### What to do
1. **Give contracts an explicit provenance tier**, not just a lock bit:
   `offline-inferred` (weakest, pattern-matched) → `ai-inferred` (LLM synthesis
   from real scanned context) → `user-confirmed` (a human explicitly approved
   it). Only `user-confirmed` should be treated as untouchable.
2. **Auto-formed (non-user-confirmed) contracts should be revisited**, not
   frozen:
   - If AI becomes configured after an `offline-inferred` contract was locked,
     propose regenerating it via the richer AI path and let the user accept or
     keep the old one — don't silently keep serving the weaker version forever.
   - If the underlying code has changed substantially since the contract was
     formed — `freshness.py` already tracks file modification vs. last-scan
     staleness, reuse that signal — flag the contract itself as possibly stale
     and prompt for reconfirmation, rather than trusting a frozen snapshot
     indefinitely.
3. **Never silently overwrite a `user-confirmed` flow** — that part of the
   original design is correct and should stay. The fix is specifically for the
   auto-formed, never-reviewed-by-a-human case, which is currently treated with
   the same permanence as an explicit human decision.
4. **Fix `_ROUTE_TO_FLOW`'s specificity problem** while this is being reworked —
   either generalize the table to genuinely common web-app patterns (not
   Patchi's own feature names) or require corroborating file-content evidence
   before applying a specific label, falling back to the generic
   `"{prefix} Endpoints"` naming when confidence is low rather than confidently
   asserting a specific meaning from a route-name collision alone.

### Acceptance check
Form a contract with no AI configured, confirm it's tagged `offline-inferred`.
Configure AI and rescan — confirm the tool proposes an upgrade rather than
silently keeping the old contract or silently discarding user edits.

---

## 5. Audit for the Same Pattern Elsewhere

`contract.py`'s `critical: bool = True` is a specific instance of a general
failure mode: a severity/importance field that looks like it was computed but
is actually a static default nobody ever assigns conditionally. Before
considering this spec done, check whether the same pattern exists in:
- `core/security/confidence_gate.py`'s severity bonus logic
- `core/agents/governor.py`'s `PhaseCriteria` defaults (already flagged in
  Part 1 §2 for being count-based rather than evidence-based — check
  specifically whether any of those numbers are similarly unearned defaults)
- `core/fix/risk_gate.py`'s ALLOW_AUTO threshold

Don't assume these are broken — check them the same way this spec checked
`contract.py`, by actually reading whether the field is ever conditionally
computed or just defaulted. Report what's found either way.

---

## Sequencing

This spec sits between Part 3 and Part 4:
1. Part 3 — linking pass, dependency gap (already speced)
2. **This spec** — the modules that produce "understanding" need to actually
   produce it before anything downstream trusts their output
3. Part 4 — the living knowledge doc, which directly depends on §1 (accurate
   criticality) and §3 (complete capability inventory) from this spec to be
   trustworthy rather than confidently wrong in a nicer format
4. Part 2 §3 / Part 1 — the AI harness and eval-set work, which benefits from
   the same evidence-based verification pattern this spec applies to doc
   validation (§2b's fix is a small-scale preview of that same approach)
