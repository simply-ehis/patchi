# Patchi — Living Knowledge Doc Spec (Part 4)

Goal: `p docs` (new command) generates a project architecture document — like the
attached `ARCHITECTURE.md` example, but better: every structural claim traced to
a real graph node, diagrams generated from real data instead of drawn by AI, and
the whole thing re-checked against the code on every scan so it can't silently
go stale. This also becomes the portable, low-cost context artifact for starting
new AI conversations elsewhere about this codebase.

**This is a linking task, not a new-feature task.** Every core ingredient already
exists in `core/brain/` — `contract.py`, `doc_validator.py`, `understander.py`,
`symbol_graph.py`, `import_graph.py`, `route_mapper.py`, `freshness.py`. Nothing
currently combines them. Confirm this before starting: none of them are called
together anywhere in `cli/commands/`.

---

## 0. Non-Negotiable Rules (same as prior specs, plus one)

1. Extend, don't rebuild — every module listed above is a building block, not
   something to reimplement.
2. No half-fixes.
3. Every claim in the generated doc needs evidence — a `file:line` it traces to.
4. **New: no section of this doc may be written by AI without first being
   grounded in graph data.** If a section can be produced by formatting Brain's
   existing structured output, it must be — AI is only for narrating facts
   already extracted, never for producing facts itself.

---

## 1. Two-Tier Content Model

### Tier 1 — Pure rendering (no AI call at all)
Directly formatted from data Brain already has:
- Project tree, file/component/route/service counts (`scanner.py`, `route_mapper.py`)
- Route table grouped by purpose (`route_mapper.py`'s `RouteInfo`)
- DB schema table, if the target project has ORM models Brain can parse
- Env vars / config surface, build/dev commands
- Key abstractions list — pull from `symbol_graph.py`'s highest fan-in/fan-out
  nodes (the things everything else depends on), not a guess
- Dependency graph raw data (for Tier 2's diagrams to consume)

None of this should ever require an AI call to produce. If a target project
lacks AI configured at all, this tier should still fully render.

### Tier 2 — Scoped AI narration, one unit at a time
For each of these, one AI call, one narrow unit of input, structured output required:
- **One paragraph per abstraction** (from Tier 1's list) — the AI is handed only
  that symbol's definition + its actual call sites via `Understander.get_function_at()`
  and `core_files()`, nothing else. It must not receive the whole file or repo.
- **One flow narrative per selected user journey** (see §2) — the AI is handed
  the actual call chain for that one flow (from `import_graph.py`/route→service
  trace), and writes what happens in plain language. It does not get to invent
  steps that aren't in the chain it was given.
- **The functionality-check narrative** — built directly on top of `contract.py`'s
  existing App Contract (critical flows that must never break); this becomes the
  "functionality checks" section almost for free — render what the contract
  already tracks, narrate briefly why each flow is load-bearing.

Every AI-written sentence in Tier 2 carries a `(file:line)` reference back to
what it was shown. This is what makes §3 (verification) possible.

---

## 2. Diagram Generation — Code Draws Them, AI Only Picks Which

- **Dependency/architecture diagram**: generate Mermaid directly from
  `import_graph.py`'s edges. This is pure code — a graph structure renders
  straightforwardly into a Mermaid `graph` or `flowchart` block. Never ask AI
  to "draw" this; there is no ambiguity to resolve, only formatting.
- **Sequence diagrams for key flows**: same approach — walk the actual call
  chain for a flow (request → route → service → downstream calls) from the
  graph and emit a Mermaid `sequenceDiagram` block from the real edges.
- **The one bounded AI decision**: picking *which* 3-5 flows are worth a
  sequence diagram, out of every route/entry point that exists. Give the AI the
  enumerated candidate list (all routes/entry points with usage/fan-in data)
  and have it pick N — this is a bounded selection from a known set, the same
  safe pattern already used elsewhere in this codebase (e.g. the pentest tool
  picker choosing from a fixed list). It must not be allowed to describe a flow
  that isn't in the candidate list.

---

## 3. Self-Verification — This Is What Proves the Brain Understands

Extend `doc_validator.py` (currently checks README claims against code) to also
check the doc's own generated claims:
- Every Tier 2 sentence's `(file:line)` citation gets re-checked on each scan —
  does that file/line/symbol still exist, and does it still do roughly what was
  described (e.g., function signature unchanged, still called from the same
  places)?
- If a citation no longer resolves, or the underlying flow's call chain has
  changed since the doc was generated, flag it as a **documentation drift**
  finding — surfaced the same way any other finding is, not buried.
- This means the doc isn't "accurate when written," it's "continuously checked" —
  that's the actual proof of understanding: not confident prose, but a citation
  trail that gets re-verified every time the code changes.
- Tie this into `freshness.py` — a section only needs regenerating if the graph
  nodes it cites have actually changed since the doc's last generation. Don't
  regenerate the whole doc from scratch every scan; regenerate only stale sections.

---

## 4. Versioning — Turns This Into a Decision Log

- Store each generated doc as a snapshot (timestamped, keyed to the scan/commit).
- On regeneration, diff against the prior snapshot and surface what changed
  architecturally (new abstraction, a flow's call chain changed, a route
  disappeared) as part of scan output.
- This directly serves "rethink decisions" — the user sees drift they may not
  have consciously intended, the same way a changelog would, but derived from
  actual structural change instead of commit messages.

---

## 5. The `p docs` Command

- New CLI command. Runs Tier 1 unconditionally (works with zero AI configured).
  Runs Tier 2 if AI is available; otherwise clearly marks those sections
  "unavailable — AI not configured" rather than leaving them blank with no
  explanation.
- Output: a single Markdown file matching the shape of the example doc
  (Table of Contents, numbered sections, Mermaid diagrams, tables) — designed
  explicitly to be portable. It should be immediately useful pasted into a new
  AI conversation elsewhere as compressed, trustworthy context — that's a
  primary use case, not an afterthought.
- Should work identically whether triggered from CLI or web dashboard, per the
  project's own "1:1 CLI ↔ Web" design principle — don't create a fifth orphaned
  feature reachable from only one surface.

---

## Acceptance Check

- Run `p docs` on a project with no AI configured — Tier 1 content (tree,
  routes, schema, abstractions list, dependency diagram) must fully render,
  with Tier 2 sections clearly marked unavailable rather than silently missing.
- Run it again with AI configured — Tier 2 narration appears, every sentence
  carries a `file:line` citation.
- Manually change a function signature referenced in a Tier 2 citation, rerun
  `p docs` (or the next scan) — the drift must be caught and flagged, not
  silently left stale.
- Confirm a repeat run only regenerates sections whose underlying graph nodes
  changed, not the whole document.

---

## Where This Fits in the Overall Sequence

This depends on Part 3's linking pass being underway (the Brain modules need to
actually be reachable and correctly wired before they can be combined), but can
run in parallel with Part 2's harness work since it uses the exact same scoped-
context principle (`Understander` already does for this what §3 of Part 2 asks
for generally). Treat this as validation of that harness approach in a lower-
stakes context (documentation) before trusting it for security findings and fixes.
