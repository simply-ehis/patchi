# Patchi — Zero-Documentation Understanding Spec (Part 6)

Real-world case: a project with no README, no docs directory, nothing.
`DocClaimAgent` cannot help here — it mines claims from existing prose, and
there's no prose to mine. This spec covers how the Brain builds real
understanding from evidence that has nothing to do with documentation, and
how that becomes a first-draft doc that then obeys the same verification
rules as any other doc (Part 5).

This builds directly on Part 4 (living knowledge doc) and Part 5 (doc
validator fixes, capability-vs-docs diff). Do those first — this spec assumes
the capability inventory and evidence-citation discipline from those already exist.

---

## 0. Non-Negotiable Rules (same as prior specs)

1. Extend, don't rebuild — `project_reader.py`'s manifest parsing and
   `scanner.py`'s AST extraction are the right foundations.
2. No half-fixes.
3. Every generated sentence needs a cited evidence source — doubly true here,
   since there's no existing doc to fall back on if the AI guesses wrong.
4. Never silently overwrite human-authored content, partial or otherwise.

---

## 1. Fix `_infer_purpose()` Before Building On It

### The problem
`core/brain/scanner.py::_infer_purpose()` is pure filename/path pattern
matching (`"auth" in name` → "Authentication and session management") and
says so in its own docstring: *"This is a heuristic — not AI. scanner agents
will improve on this."* No scanner agent currently does. It never reads a
file's actual content — docstrings, comments, or the function bodies already
parsed by the same AST pass that produced the filename in the first place.

This is the same failure mode as `_ROUTE_TO_FLOW` in `contract.py` (Part 5
§4): guessing meaning from naming convention instead of looking inside the
thing. In the zero-doc case, this heuristic's output becomes a primary input
to everything downstream — its weakness compounds instead of being one signal
among many.

### What to do
- Extend `_infer_purpose()` (or add a companion pass) to read the file's own
  docstrings and leading comments — content Brain already has parsed via AST,
  just not consulted here. A module docstring reading "Handles Stripe webhook
  verification and idempotent charge recording" is real evidence; a filename
  containing "handler" is a guess.
- Keep the filename heuristic as a fallback for files with no docstrings, but
  stop treating it as the primary signal once real content is available.

---

## 2. Build the Evidence Sources That Don't Depend on Documentation

None of these require any doc file to exist. Assemble them as structured,
per-component evidence — not raw text dumped into a prompt:

- **Dependency manifests** (`project_reader.py` already parses `package.json`,
  `pyproject.toml`, `Cargo.toml`, `go.mod`) — a project depending on `stripe`,
  `boto3`, `discord.py`, or `transformers` tells you its domain far more
  reliably than any filename guess. This already exists; it just isn't fed
  into a synthesis step yet.
- **Docstrings/comments** (§1) — real code content, near-zero additional cost
  since AST parsing already happens.
- **Test names and assertions** — Brain already extracts functions from every
  file it parses, including test files, for running/counting tests. Nobody
  currently reads `test_checkout_fails_with_expired_card` as a sentence about
  what the app does. Test names are some of the most reliable evidence
  available, because they're the one kind of "documentation" that breaks
  loudly (a failing test) when it stops being true.
- **Actual runtime behavior**, where a live instance is available — reuse the
  existing DAST/live-testing infrastructure (already speced for wiring into
  the CLI in Part 3) to hit real endpoints and record actual observed
  responses. "This endpoint returned a 401 with this body when called without
  auth" is empirical evidence, not an inference from a route path. Don't
  build a second probing mechanism — this is the same capability the security
  work already needs, reused for comprehension.
- **Entry points and critical directories** — `project_reader.py`'s
  `ProjectInsight` already identifies these; reuse directly.

---

## 3. Scoped Synthesis — Same Harness Discipline as Everywhere Else

For each component in the capability inventory (Part 5 §3), assemble its
available evidence into one structured packet: relevant dependency
implications, docstring content, related test names, any live-probe results,
structural position (fan-in/fan-out from the graph). Hand that packet — not
raw files, not the whole repo — to the AI for exactly one narrow task: write
1-2 sentences describing this one component, citing which evidence item(s)
justified each claim.

If a component has *no* evidence beyond a bare filename and no docstring, say
so explicitly ("purpose unclear — no docstring, tests, or usage evidence
found") rather than letting the AI invent a plausible-sounding guess to fill
the gap. An honest gap is more useful than a confident wrong answer — this is
the same principle Part 1 and Part 5 already apply to findings and claims.

---

## 4. Close the Loop — the Generated Doc Gets Verified Like Any Other

Once this produces a first-draft doc, it is not exempt from Part 5's fixes —
it goes through the same doc validator that would check a human-written
README:
- Every generated sentence's evidence citation gets re-checked the same way
  Part 4 §3 re-checks knowledge-doc citations.
- The capability-vs-docs diff (Part 5 §3) now has real content to compare
  against, closing the bootstrap problem — before this, there was no doc to
  diff against; now there's a machine-generated one that itself needs the
  same scrutiny as any other.

---

## 5. Fix Doc Discovery Being Format-Inconsistent

Directly checked: the two doc-discovery mechanisms don't agree.
- `doc_claim_agent.py`'s `_DOC_PATTERNS` (the AI-powered path) covers a wide
  net: `README*`, `*.md`, `*.txt`, `*.rst`, `CHANGELOG*`, and more.
- `doc_validator.py`'s glob (the fallback path — which Part 5 confirmed is
  what actually runs whenever AI isn't configured, the common case) only
  matches `README*`, `*.md`, `docs/**/*.md`.

A `README.txt` or `NOTES.rst` is invisible in exactly the scenario where it
matters most — no AI configured, relying on the fallback. Fix: one shared doc-
discovery function both paths call, format-agnostic (content extraction
doesn't care about the extension), used consistently everywhere doc files are
located in this project.

---

## 6. Partial-Docs Case — Fill Gaps, Never Overwrite

When some documentation exists but is incomplete (the realistic common case,
not just the two extremes):
- Run the same evidence pipeline from §2-3, but only generate content for
  capabilities the Part 5 §3 diff already flagged as undocumented.
- Never silently rewrite or replace existing human-authored doc content.
  Proposed additions are appended or presented as a suggested patch, clearly
  marked as machine-generated pending review — the same principle Part 5 §4
  already establishes for not overwriting a user-confirmed contract flow.
  A developer's existing prose is high-trust data; treat it that way.

---

## 7. Output Format

The generated doc is always Markdown, regardless of what format (or absence)
of existing docs the project has — matches Part 4's `p docs` output and is
the most portable choice (renders on GitHub, supports tables and Mermaid).
It should be written to a clearly-labeled, separate file (not silently
overwrite whatever `README.md` might already exist) unless the user
explicitly confirms they want it to seed or replace their actual README.

---

## Acceptance Check

- Run against a project with zero doc files of any kind. Confirm a first
  draft doc is generated, every sentence has a cited evidence source, and any
  component with no real evidence is explicitly marked unclear rather than guessed.
- Add a `README.txt` (not `.md`) to a project with no AI configured — confirm
  it's now discovered and used by the fallback path.
- Add partial docs missing a real, working feature — confirm only the gap
  gets proposed content, and existing prose is untouched.

---

## Sequencing

Depends on Part 4 (knowledge doc renderer) and Part 5 (capability inventory,
doc validator fixes, citation discipline) already being in place — this spec
is the "what happens when there's nothing to start from" case of the same
system, not a separate feature.
