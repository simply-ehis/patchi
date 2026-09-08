# Patchi — Linkage Guide (what to also touch, not where things are)

> Not a map of files. A map of **hidden couplings** — the "if you change X, you also need to
> touch Y or it breaks silently" knowledge that isn't obvious from reading one file in
> isolation. Every linkage below was hit and verified directly against the real code this
> session, not written from memory or assumption.

---

## Adding or upgrading language support

This is the most-coupled area in the whole codebase. A new language touches up to **six
separate places**, and missing one doesn't crash — it just silently produces nothing, which is
worse, because nothing tells you it's missing.

1. **`patchi/core/brain/languages.py`** — the `Lang` enum, the extension → `Lang` map, and
   `get_parser(lang)`'s dispatch. This is the root; nothing else works without this.
2. **`patchi/core/brain/scanner.py`** — `_parse_by_language`'s `if lang == Lang.X:` chain, plus
   the actual `_parse_X` walker function. Without this, files of that language get silently
   routed to `_parse_generic` (a no-op) instead of erroring — confirmed this exact failure mode
   for Scala this session.
3. **`patchi/core/brain/type_checker/__init__.py`**'s `_get_checker`'s `if lang == Lang.X:`
   chain, plus a real `type_checker/{lang}.py`. Called from exactly one place —
   `core/agents/type_scanner.py` — confirmed directly, not assumed. A perfectly good
   `type_checker/{lang}.py` file does nothing if `_get_checker` doesn't route to it.
4. **`patchi/core/brain/route_detector/{lang}.py`** (if the language has a web framework worth
   route-mapping) — **and this is the trap**: a correct route detector is dead code without
   two more things:
   - `patchi/core/brain/framework.py` needs a `_detect_X` method that can actually recognize the
     framework exists in a project (checking for its manifest file — `.csproj`, `pom.xml`,
     `go.mod`, etc.). Built the C# detector this session and initially missed this exact
     piece — a fully correct route detector that never ran, because nothing could tell
     `route_mapper.py` that ASP.NET Core was even present.
   - `patchi/core/brain/route_mapper.py`'s `_LANG_FW_MAP` needs `"lang_key": {"Framework Name"}`,
     and `extract()`'s detector-population loop needs the corresponding `elif`.
5. **`patchi/core/brain/symbol_graph.py`** (if cross-file symbol/dead-code tracking should work
   for the language) — needs a `_walk_X`/`_extract_X` pair.
6. **Language string consistency** — every one of the above keys off `Lang.X.value` (e.g.
   `"c_sharp"`, not `"csharp"`, not `"C#"`). Use the enum value everywhere, never a hand-typed
   string, or the dispatch chains silently miss each other.

**Quick self-check after adding a language:** actually build a tiny real sample project on disk
and run `FileScanner → FrameworkDetector → RouteMapper` (or whichever pieces apply) end to end,
the way the C# detector was verified this session. A passing compile step proves nothing here —
these are dispatch-chain miss failures, not syntax errors, and only a real run catches them.

---

## Adding or upgrading a security domain / control

- `domains/{domain_id}.yaml` and `fix-playbooks/{domain_id}.playbook.yaml` **must share the
  exact same `domain_id`** as both the field value and the filename. A mismatch doesn't error —
  it just makes the pairing silently fail, which looks identical to "no fix playbook written
  yet." This exact confusion already happened once this session.
- Schema is not flexible — `domain_loader.py` expects exact field names:
  `domain_id`/`version`/`display_name`/`source_standard`/`component_type`/`weight`/
  `activation_signals`/`controls[].{control_id,name,description,source_clause,severity,
  check_method,detector,remediation_ref}` for domains; `control_id`/`playbook_version`/
  `fix_strategy`/`deterministic_tool`/`llm_fix_template`/`verification_checks`/
  `blast_radius_notes` for fix-playbooks. Drift here isn't caught by any type system — verify
  against `domain_loader.py` directly, not against another YAML file that might itself be wrong.
- `activation_signals` need to be genuinely detectable (a real package name, a real code
  pattern) — a vague signal means the domain either never activates or always does, both silent
  failure modes.
- The plain `playbooks/` directory (as opposed to `fix-playbooks/`) is **not read by
  `domain_loader.py` at all** — confirmed directly, only `domains/` and `fix-playbooks/` are
  consumed. Don't spend effort maintaining it under the assumption it's live.

---

## Adding a new scanner agent (`core/agents/` or `core/security/`)

- Must use the `@register` decorator (`BaseAgent` pattern) or `Coordinator` never discovers it.
- Use `logging.getLogger("patchi.<module>")` for anything that can fail — never a silent
  `except Exception: pass`. This isn't a style preference; 424 of these were found and fixed
  this session specifically because they hide real scan failures as false-clean results.
- `DEFAULT_IGNORE_DIRS` handling is currently **inconsistent** across existing agents (some
  hand-roll their own exclusion list, most don't) — the Scan Bus design (§1, not yet built)
  centralizes this into `FileCorpus`. Until that lands, a new agent should still respect
  `DEFAULT_IGNORE_DIRS` explicitly rather than assume it's handled upstream.
- If the agent proposes fixes (not just findings), route the decision through `risk_gate.py`'s
  `RiskGate` — don't have the agent itself decide "this is safe to auto-apply." See Mode/safety
  section below.

---

## Adding a new fix agent (`core/fix/`)

- Follow `applier.py`'s pattern: snapshot before, verify after, rollback on failure — and track
  whether rollback *actually succeeded*, don't assume it did. A real bug here (rollback failure
  silently reported as success) was found and fixed this session.
- AI-calling fix agents should log to the audit trail via `patchi_action_log`
  (`core/security/governance.py`). A silent failure here means the audit trail has gaps with no
  record that anything's missing — also a real bug found and fixed this session.
- Set `ProposedFix.safe` conservatively and correctly. Planned CI/PR work (`p fix --safe-all`)
  will trust this field to decide what gets auto-applied in a batch with no per-fix review.

---

## Mode / safety / "can this auto-approve?"

This is governed in exactly one place: `core/fix/risk_gate.py`'s `RiskGate`, gating against
`core/constants.py`'s `Mode` enum (`CONFIRM` = everything needs approval, `AUTO` = safe fixes
auto-apply, `AUTOPILOT` = full trust). **A new agent or fix should never unilaterally decide
it's safe** — it should produce a risk score / the `safe` boolean and let `RiskGate` make the
call. `RiskGate` itself is designed to never raise and always fail toward the safer mode on any
internal error (config/brain load failure defaults to `CONFIRM`, the strictest setting) — don't
weaken that fallback direction when touching this file.

---

## Queue / parallel execution — a real current gotcha, not a design opinion

**As of this session, `core/queue.py` is not what actually runs your scan.** Confirmed directly:
nothing in the scan pipeline imports it. Actual parallel execution today goes through
`core/agents/coordinator.py`'s `Coordinator.run_group`/`run_agents`, not the queue.

`queue.py` *is* used by real callers, just not for scanning: `queue_cmd.py` (full queue
management — list, stats, pause, resume, skip, clear, mode), `web/app.py` (dashboard rendering),
`web/api_legacy.py` (legacy web API queue operations), and `status_cmd.py` (status overview).
But it is a display/management layer, not an execution layer.

The Scan Bus design (§1, not yet built) plans to make the queue the *actual* execution path via a
new `QueueRunner` — but that's still a design on paper, not current behavior. **If you're adding
something new today that should run in parallel, wire it through `Coordinator`, not `queue.py`
— even though the queue "looks" like the right place.** This will change once Scan Bus lands;
until then, trust what's actually verified, not what looks architecturally correct.

---

## Anything that should show up in the Cockpit (`p cockpit`)

`core/brain/cockpit.py` only reads from five specific signal sources: `health.compute`,
`audit.compute_drift`, `proactive.build_fix_list`/`rank_fixes`, `reasoning.impact_analysis`,
`secrets.scan_secrets`. A new finding/fix source built entirely outside these five won't appear
in the cockpit automatically — either route through one of them, or update `cockpit.py`'s
gatherers to add a sixth source.

---

## Performance-sensitive changes — cache within one operation's scope

If you're writing anything that reads the same set of files more than once inside a single
scan/check (e.g. searching for a symbol's usage across every other file), **cache the reads for
the duration of that one call** rather than re-reading per iteration. A real O(n²) bug of
exactly this shape was found in `proactive.py`'s dead-code checker this session — redundant
re-reads of every other file, once per candidate symbol, made a whole-project scan effectively
hang. Once Scan Bus's `FileCorpus` lands, this becomes automatic (parse-once, shared); until
then, it's a manual discipline.

---

## The recurring pattern worth recognizing on sight

`scanner.py`'s `_parse_by_language`, `type_checker/__init__.py`'s `_get_checker`, and
`route_mapper.py`'s detector population all use the **same shape**: an explicit
`if lang == Lang.X:` dispatch chain, not auto-discovery from a directory listing. This is
consistent across the codebase — if you're adding a new capability for an existing language and
it doesn't seem to be firing, the answer is almost always "missing from one of these dispatch
chains," not a bug in the new code itself. Check the dispatch chain before debugging the new
file.
