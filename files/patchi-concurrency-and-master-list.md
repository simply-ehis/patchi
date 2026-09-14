# Patchi — Concurrency Fix & Master Item List (Part 8)

## Part A: The Concurrency Fix

### The exact problem, confirmed by a reproduced crash
`core/agents/governor.py::_get_conn()`:
```python
def _get_conn(self) -> sqlite3.Connection:
    if self._conn is None:
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
    return self._conn
```
WAL mode is set, but **`busy_timeout` is never set** — zero hits anywhere in
`governor.py`. Same gap in `core/brain/symbol_graph.py`. This is the exact,
confirmed cause of the crash already observed in testing:
```
Governor.close checkpoint failed: database table is locked
```
`close()` runs `PRAGMA wal_checkpoint(TRUNCATE)` and `PRAGMA journal_mode=DELETE`,
both of which need exclusive access. With no busy timeout, if any other
connection is active at that moment — plausible given the Governor dispatches
up to 248 agents in a single phase — it fails immediately instead of waiting.

The fix is already correct, in the same codebase, unused where it's needed:
`core/security/governance.py`:
```python
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA busy_timeout=10000")
# WAL + busy_timeout make concurrent writers (parallel agents calling...) [work]
```

### What to do
1. Add `PRAGMA busy_timeout=10000` (or a tuned value) everywhere `journal_mode=WAL`
   is set without it — confirmed missing in `governor.py` and `symbol_graph.py`.
2. Audit the other db files found during this investigation for the same gap:
   `flake_history.db`, `patchi_actions.db`, `patchi_history.db`,
   `snapshot_drift.db`, `zone.db` — each needs the same check applied, not
   assumed fine by association.
3. Add a retry/backoff wrapper around operations that can legitimately still
   hit `sqlite3.OperationalError` even with a timeout (e.g. very long-held
   locks) — `busy_timeout` reduces the problem, it doesn't guarantee zero
   contention under heavy parallel load.
4. Don't silently swallow the error if a retry ultimately still fails — surface
   it, per the honesty theme from Part 2, rather than logging a warning after
   the fact and still reporting the pipeline as passed.

### Acceptance check
Reproduce the original failure condition (concurrent agent writes during a
Governor run) with the fix applied — confirm `Governor.close` no longer throws
"database is locked" under the same load that produced it before.

---

## Part B: Master Item List — All Specs, Intentionally Unordered

Every item from Parts 1–8, deliberately **not** arranged by priority or
dependency. Sequencing was already given inside each individual spec (each
one ends with its own "Sequencing" section) — pulling everything into one
shuffled list here on purpose, so the ordering below carries no signal.
**Do not treat list position as priority.** Determine actual sequencing from
the dependencies already explained inside each originating spec, not from
where an item happens to fall in this list.

1. Add `busy_timeout` to `symbol_graph.py`'s SQLite connection (Part 8)
2. Build the standing eval set — labeled true/false-positive cases (Part 1 §5)
3. Fix `_infer_purpose()` to read docstrings before falling back to filename patterns (Part 6 §1)
4. Wire DAST into a CLI-reachable path, not just the web dashboard (Part 3 §1)
5. Fix the Governor's phase-transition violations being logged then ignored (Part 2 §2b)
6. Build the code-derived capability inventory (routes, CLI commands, classes) independent of docs (Part 5 §3)
7. Add an explicit authorization/scope confirmation gate before active pentest tools fire (professional-tool discussion)
8. Fix `p test` reporting "All tests passed" on zero tests (Part 2 §2d)
9. Audit `confidence_gate.py`'s severity logic for the same static-default pattern as `contract.py` (Part 5 §5)
10. Build Tier 1 pure-rendering sections of the knowledge doc — tree, routes, schema, abstractions (Part 4 §1)
11. Fix `p init`'s non-interactive `EOFError` crash and its exit-code-0-on-failure bug (Part 2 §4)
12. Retry/backoff wrapper for lingering `OperationalError` cases after the busy_timeout fix (Part 8)
13. Resolve the open 32-vs-74 duplicate-scanner discrepancy in `AGENT_FEEDBACK.md` (Part 1 §3)
14. Fix `brain.py`'s `_infer_project_purpose()` stacking one heuristic's output on another (Part 7 §2)
15. Merge the Governor into base `p scan`, delete the `--governor` flag entirely (Part 2 §1)
16. Build one unified external-tool dependency registry — 9 of 15 tools currently unchecked by `p doctor` (Part 3 §2)
17. Diff the code-derived capability inventory against the docs to catch undocumented features (Part 5 §3)
18. Fix `contract.py`'s `critical: bool = True` static default — compute from blast radius, test coverage, external-facing surface (Part 5 §1)
19. Build the client-ready report format — executive summary, evidence screenshots, remediation steps (professional-tool discussion)
20. Fix `p ready`'s hardcoded 3-agent security shortlist to reflect real coverage (Part 3 §1)
21. Build test-name/assertion extraction as comprehension evidence for the zero-doc case (Part 6 §2)
22. Systematically sweep all ~72 regex-touching files in `core/brain`/`core/agents`/`core/security`, classify KILL vs KEEP-AND-HARDEN (Part 7 §3)
23. Fix the Governor's score-vs-reverify mismatch — fix candidates scoring 1.00 despite unresolved findings (Part 2 §2a)
24. Build install hints and a real install path (`p doctor --install` or similar) for every missing tool (Part 3 §2)
25. Reconcile the documented-but-nonexistent `p security` command against the actual CLI (Part 3 §1)
26. Tie `charter.py`/`restrict` scope enforcement into the DAST/pentest registry — currently zero enforcement (professional-tool discussion)
27. Give the contract explicit provenance tiers — offline-inferred / ai-inferred / user-confirmed — and stop permanently locking auto-formed ones (Part 5 §4)
28. Build reject-and-retry logic for AI calls that fail schema validation (Part 2 §3)
29. Fix doc discovery's format inconsistency — `.txt`/`.rst` invisible in the common no-AI fallback path (Part 6 §5)
30. Audit `domain_activator.py`'s `_infer_primary_language`/`_infer_app_type`/`_infer_deployment` for the same guessing pattern (Part 7 §3)
31. Build Mermaid diagram generation directly from `import_graph.py`/`route_mapper.py` data (Part 4 §2)
32. Fix the swallowed `Governor.close` checkpoint error — surface it instead of hiding it behind "Pipeline PASSED" (Part 2 §2c)
33. Build dependency-manifest-based project classification, replacing filename-guess stacking (Part 6 §1 / Part 7 §2)
34. Make every agent report "skipped: tool missing" as its own distinct status, not a silent empty result (Part 3 §2)
35. Close the testing-depth gaps: mutation testing, flaky-detection wiring, coverage-guided prioritization, contract test generation (Part 1 §6)
36. Fix `_ROUTE_TO_FLOW`'s Patchi-specific naming risk colliding with generic routes on other projects (Part 5 §4)
37. Build the scoped-context AI harness — target symbol + real call-graph neighborhood, never whole-file (Part 2 §3)
38. Extend doc validator to re-check the knowledge doc's own generated citations for drift (Part 4 §3)
39. Fix doc validator's silent skip — always print a result line, including the zero-claims case (Part 5 §2a)
40. Rewrite the Governor's `PhaseCriteria` to be evidence-based instead of count-based (Part 1 §2)
41. Build live runtime-probing as comprehension evidence, reusing the DAST infrastructure (Part 6 §2)
42. Fix doc validator's weak verification — `verified = len(evidence) >= 1` needs a real bar or a cited AI check (Part 5 §2b)
43. Tie the knowledge doc's regeneration into `freshness.py` so only stale sections rebuild (Part 4 §3)
44. Audit `risk_gate.py`'s ALLOW_AUTO threshold for the same static-default pattern (Part 5 §5)
45. Build the `p docs` CLI command — works with Tier 1 content even with zero AI configured (Part 4 §5)
46. Audit all sqlite db files (`flake_history.db`, `patchi_actions.db`, `patchi_history.db`, `snapshot_drift.db`, `zone.db`) for the missing busy_timeout pattern (Part 8)
47. Build structured output contracts every AI call must satisfy, validated before acceptance (Part 2 §3)
48. Fix Playwright browser-install detection so every Playwright-dependent agent hits the same reliable check (Part 3 §2)
49. Build the partial-docs gap-filling flow — append only, never overwrite human-authored content (Part 6 §6)
50. Audit `contract.py`'s `_infer_from_file_structure` — separate function, same file, not yet reviewed (Part 7 §3)
51. Build doc snapshot versioning/diffing to surface architectural drift over time (Part 4 §4)
52. Validate and tune `confidence_gate.py`'s thresholds against the standing eval set once it exists (Part 1 §4)
53. Audit `core/security/intent_analyzer.py` — name alone suggests the same inferred-intent-over-verified-behavior risk (Part 7 §3)
54. Make every finding/phase-pass show its evidence trail in reports, not just a verdict (Part 1 §8)
55. Build the "unclear — no evidence found" explicit fallback for zero-doc synthesis, instead of letting AI guess (Part 6 §3)
56. Enumerate every registered agent and trace whether it's actually reachable from a real CLI command, not just registered (Part 3 §1)
57. Standardize generated-doc output as Markdown in a separate file, never silently overwriting an existing README (Part 6 §7)
58. Investigate the `SBOMGeneratorAgent` 32-second-on-one-file anomaly before trusting performance at any real project scale (flagged, not yet a full spec)
59. Investigate whether generated fixes and `p undo`/`p rollback` are actually safe and correct, given the scoring layer already lies (flagged, not yet a full spec)
60. For every KEEP-AND-HARDEN heuristic, require an explicit compulsory-reason comment plus a measured precision/recall entry — never the sole source of a final verdict (Part 7 §4)
