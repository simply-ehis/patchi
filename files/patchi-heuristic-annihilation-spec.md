# Patchi — Heuristic & Regex Annihilation Pass (Part 7)

Every module fixed so far (Parts 1, 2, 5, 6) turned out to share one disease:
something guessed at meaning using a name, a keyword, or a regex pattern, and
that guess got treated as fact downstream. This pass generalizes the fix
across the whole codebase instead of module-by-module.

**The rule going forward: a heuristic dies unless it's compulsory. If it's
compulsory, it doesn't get to stay weak — it gets measured and held to a bar.**

---

## 0. The Line — What Actually Dies vs. What's Legitimate

Not everything pattern-based is the problem. Draw this distinction explicitly
before touching anything, so the pass doesn't break things that are already correct:

**Legitimate — leave alone:**
- Detecting a tech stack from the *presence* of a real file (`requirements.txt`
  → Python, `package.json` → Node). This is reading a fact, not guessing one.
  `framework.py`'s `_detect_python()`, `_detect_node()`, etc. are fine.
- File-extension-based language detection.
- Regex used purely to *locate candidate text* before a real check runs on it
  (e.g., finding sentences that look claim-shaped before verifying them) —
  fine as a first-pass filter, never fine as the final verdict.

**Illegitimate — this is what dies:**
- Guessing what a file/route/flow *means* or *does* from its name instead of
  its actual content or structure, when the real content is already parsed
  and available.
- Calling something "verified," "critical," or "confirmed" based on a
  keyword/token match instead of a real structural or cited check.
- A heuristic's output feeding directly into another heuristic with no real
  signal in between, compounding a guess into a bigger guess.

---

## 1. Confirmed Cases (already found across Parts 1–6 — the seed list)

| Location | What it does wrong | Fix already specified |
|---|---|---|
| `contract.py` — `_ROUTE_TO_FLOW` / `INFERENCE_RULES` | Hardcoded route-name-to-meaning table, specific enough to look copy-pasted from Patchi's own dashboard | Part 5 §4 — generalize or require corroborating evidence, fall back to generic naming when uncertain |
| `contract.py` — `ContractFlow.critical: bool = True` | Static default, never computed | Part 5 §1 — derive from blast radius, test coverage, external-facing surface |
| `scanner.py` — `_infer_purpose()` | Pure filename pattern matching; docstring admits it's a stopgap ("not AI... scanner agents will improve on this") never acted on | Part 6 §1 — read docstrings/content first, filename guess as last resort only, explicitly marked low-confidence |
| `doc_validator.py` — `_CLAIM_PATTERNS` | Regex extraction is fine as a candidate-finder; the problem is what happens next | Part 5 §2b |
| `doc_validator.py` — `cross_reference_claim()` | `verified = len(evidence) >= 1` — one overlapping token anywhere in the whole codebase counts as proof | Part 5 §2b — kill this outright, replace with structural match or cited AI check |
| `governor.py` — `PhaseCriteria` | Phase "done" gated on error/finding counts, not on whether anything was actually verified | Part 1 §2 |
| **New — `brain.py::_infer_project_purpose()`** | The no-AI fallback for "what does this app do" — the single most important sentence the whole system produces — is built by keyword-matching (`"web" in p.lower()`) against `fi.purpose` strings, which are themselves `_infer_purpose()`'s filename guesses. A heuristic guessing off another heuristic's output, for the highest-stakes answer in the system. | New — see §2 below |

---

## 2. Fix `_infer_project_purpose()` — Stop Stacking Guesses

### The problem, precisely
```python
has_web = any("web" in p.lower() or "route" in p.lower() or ... for p in purposes)
```
`purposes` here is `fi.purpose` for every file — the output of the already-weak
`_infer_purpose()` filename heuristic. This function doesn't even use the
stronger signal that already exists: `project_reader.py`'s real dependency
manifest data (`stack.frameworks` is pulled in only for a display string, not
for the actual category classification logic).

### What to do
- Classify project category primarily from **dependency manifest data**
  (`project_reader.py`'s already-parsed `package.json`/`pyproject.toml`/etc.) —
  a project depending on `fastapi` + `sqlalchemy` is reliably a web API with a
  database; a project depending on `discord.py` is reliably a Discord bot.
  This is real, not guessed.
- Use `fi.purpose` values only after §1's fix to `_infer_purpose()` makes them
  content-derived rather than filename-derived — otherwise this function keeps
  inheriting the same weakness one level up.
- If dependency signal is thin (no manifest, unusual stack) and file-purpose
  signal is also thin, say so explicitly ("project type unclear from available
  signals") rather than assembling a guess from a guess.

---

## 3. The Systematic Sweep

This can't be done from the handful of cases already found — a grep across
`core/brain/`, `core/agents/`, and `core/security/` for `re.compile`/`re.search`/
`re.match` turns up **72 files**. Every hit needs to go through the classification
in §0. Concrete starting points beyond the confirmed cases above, found in the
same pass and not yet individually audited:

- `core/brain/domain_activator.py` — `_infer_primary_language()`,
  `_infer_app_type()`, `_infer_deployment()`
- `core/brain/contract.py` — `_infer_from_file_structure()` (separate from
  `_ROUTE_TO_FLOW`, not yet checked)
- `core/security/intent_analyzer.py` — name suggests exactly this category of
  risk (inferring intent from pattern rather than verified behavior)
- `core/assurance/graph.py`, `core/brain/import_graph.py` — flagged by the
  same grep, not yet individually reviewed

### Process
1. For each hit, apply the §0 test: is this reading a fact, or guessing a
   meaning? Is its output ever labeled "verified"/"critical"/"confirmed"
   downstream without a real check in between?
2. Classify as **KILL** (replace with real signal — AST content, dependency
   data, graph structure, actual verification) or **KEEP-AND-HARDEN**
   (compulsory — see §4).
3. Track this as an actual checklist (same discipline as Part 3's linking-pass
   audit) — a table of file, function, classification, and status. Don't let
   "found some, fixed some" pass as complete; the list needs to resolve to zero
   open items or an explicit, justified KEEP-AND-HARDEN entry.

---

## 4. The Compulsory Cases — Improve Until They Survive

Some heuristics are genuinely necessary and shouldn't be killed:
- **`confidence_gate.py`'s scoring thresholds** — you cannot AI-verify every
  finding at scale; a fast numeric gate is the right tool here. This is the
  canonical KEEP-AND-HARDEN case.
- **Secret/credential detection** (entropy-based, pattern-based in
  `EnvScanner` and similar) — there's no structural proof that a string is an
  API key; pattern/entropy heuristics are the actual right approach here.
- **Regex as a candidate-finder** before a real check (§0) — legitimate by design.

For every case classified KEEP-AND-HARDEN, it must have:
1. **An explicit comment stating why it's compulsory** — not "this was
   convenient," but the actual structural reason a real check isn't possible
   or affordable here.
2. **A measured precision/recall entry in the standing eval set** (Part 1 §5).
   "Compulsory" doesn't mean "trusted by default" — it means "the fast path,
   proven to be good enough by measurement." The 32-vs-74 discrepancy already
   found in `AGENT_FEEDBACK.md` is almost certainly rooted in exactly this
   category of unmeasured threshold — this sweep is how it actually gets closed.
3. **Never the sole source of a final verdict.** A KEEP-AND-HARDEN heuristic
   can gate what gets checked further, or serve as a fast prefilter — it
   cannot, by itself, produce a "verified," "critical," or "confirmed" label
   with nothing downstream double-checking it.

If a KEEP-AND-HARDEN candidate can't clear a reasonable accuracy bar once
measured, it doesn't get to stay "because it's fast" — slow-and-right beats
fast-and-wrong for a testing/security tool. Re-open it as a KILL candidate.

---

## Acceptance Check

- Produce the full audit table from §3 — every regex/heuristic hit in the
  three directories, classified, with either a fix applied or a justified
  KEEP-AND-HARDEN entry backed by a real measurement.
- Re-run the 32-vs-74 discrepancy check from Part 1 §3 after this pass —
  confirm whether it's now resolved or at least explained by a specific,
  now-measured threshold.
- Spot-check `_infer_project_purpose()` on a project with a clear, unusual
  dependency stack (e.g., a Discord bot) with no AI configured — confirm it's
  now classified from manifest data, not compounded filename guesses.

---

## Sequencing

Do this after Parts 5 and 6 (the specific fixes already scoped there are part
of this pass's seed list, not separate work) and alongside Part 3's linking
audit — both are full-codebase sweeps and can reasonably share the same pass
rather than being done twice.
