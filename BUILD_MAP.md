# BUILD MAP — Patchi (CLI/Core scope only)

**Last Updated:** 2026-08-06
**Phase:** Domain taxonomy expansion + checker specificity + Sigma rules + test coverage
**Scope note:** `patchi/web` is explicitly OUT of scope for this work — CLI + core only.

---

## Domain Taxonomy — Current State (2026-08-06)

| Category | Count | Sources |
|---|---|---|
| **Domains** | 334 | ASVS 5.0, OWASP Top 10:2025, OWASP API Security, CWE Top 25, Cloud, DevSecOps, Cryptography, Network, Data Protection, Mobile, Compliance, AI/ML, IoT/SCADA, Fintech, Healthcare, Telecom, Blockchain, XR, NIST SP 800-53, CIS Controls v8, PCI DSS 4.0 |
| **Playbooks** | 335 | Generated from domain YAML controls |
| **Fix-playbooks** | 335 | Generated from domain YAML controls |
| **Sigma rules** | 17 | SQL injection, XSS, SSRF, path traversal, command injection, brute force, credential stuffing, hardcoded secrets, debug mode, CORS, lateral movement, dependency confusion, container escape, JWT none algorithm, CSRF |
| **Domain checkers** | 334 | Every domain has a registered checker in `_DOMAIN_CHECKERS` |
| **Auto-generated checkers** | 286 | In `_generated_checkers.py` for unwired domains |
| **Domain-specific signal mappings** | ~80 | In `gen_checkers.py` DOMAIN_SIGNALS dict |

### Checker Specificity (tightened 2026-08-06)
- `has_backend_api_surface` narrowed from `ctx.has_web or bool(ctx.routes) or bool(ctx.imports)` to `bool(ctx.routes) and (ctx.has_web or framework import)`
- `has_database_surface` narrowed from `bool(ctx.deps)` to specific DB imports
- Added ~80 domain-specific signal mappings to eliminate false positives for verticals (IoT, blockchain, healthcare, fintech, telecom)

### Activation Results
- Minimal CLI: 1 domain (supply-chain-local-tool)
- Patchi (self-scan): 39 domains
- Flask app: 182 domains
- Zero false positives for verticals when no matching signals

---

## Known Issue Inventory (from AUDIT_STUBS_PLACEHOLDERS_WRONG_LOGIC.md, independently verified)

The existing audit doc claimed several things were "fixed" — some were wrong or stale. Verified truth as of this session:

| Item | Doc claimed | Actual verified state |
|---|---|---|
| MD5→SHA256 (scan_cmd.py) | ✅ Fixed | ✅ Confirmed true |
| CORS wildcard (web/app.py) | ✅ Fixed | ✅ Confirmed true (web scope, not touched here) |
| `_is_quiet_hours` minutes bug | ❌ Still broken | ✅ Actually already fixed in code — doc is stale |
| Silent exception swallowing | "200+ instances" | **424 instances** confirmed via grep, doc undercounted |
| Old-style agent signatures | "26 agents" | **35 agents** confirmed via grep, doc undercounted |

## Silent Exception Swallowing — Progress Tracker (424 total across core/ + cli/)

| Directory | Count | Status |
|---|---|---|
| `core/brain` (incl. `type_checker`, `route_detector`, `ast_utils`) | 164 | ✅ DONE (this session) |
| `core/security` | 95 | ✅ DONE |
| `cli` | 59 | ✅ DONE |
| `core/agents` | 54 | ✅ DONE |
| `core/testing` | 22 | ✅ DONE |
| `core/fix` | 14 | ✅ DONE |
| `core/*.py` (root) | 8 | ✅ DONE |
| `core/detector` | 3 | ✅ DONE |
| `core/hosted` | 2 | ✅ DONE |
| `core/ai` | 2 | ✅ DONE |
| `core/notifications` | 1 | ✅ DONE |

## 🏁 PROJECT COMPLETE: 424 of 424 silent exception handlers fixed

Verified with a full project-wide `grep` across all of `patchi/core` + `patchi/cli` — **0 remaining bare `except Exception:` blocks.** Not assumed from batch arithmetic; directly re-checked.

**Convention established:** use existing `logging.getLogger("patchi.<module>")` pattern (already used in `security_agents.py`, `confidence_gate.py`, `detection_pipeline.py`). Module-level `_log` variable, not inline calls. Severity: `_log.warning()` for anything affecting correctness/state/audit trail, `_log.debug()` for benign fallback-strategy paths (e.g. trying jest then npm).

---

## Files Touched

### `patchi/core/fix/applier.py`
**Does:** Applies a patch to disk — snapshot, write, run tests/linter, rollback on failure, verify, persist state.
**Depends on:** `patchi.core.memory`, `patchi.core.snapshot`, `patchi.core.fix.patch`
**Changes made this session:**
- Added `logging.getLogger("patchi.fix.applier")`
- **Fixed real logic bug:** rollback-after-failed-write path used to unconditionally report `rolled_back=True` even if the rollback itself failed. Now tracks actual outcome and reports honestly.
- **Fixed real bug found via new logging:** `_update_patch_state()` never created its parent directory before writing, so patch history silently failed to persist on any fresh project (confirmed via direct repro — fired the new warning immediately). Fixed by adding `mkdir(parents=True, exist_ok=True)`, matching the pattern `memory.py` already uses internally.
- Logged: audit-trail write failures, brain-stale-marking failures, verify_fix failures, jest/npm config-parse fallbacks (debug level).
**Notes:** 5 pre-existing test failures in `tests/test_applier.py` (unrelated to this session's changes — confirmed identical failures on the original unedited file). Root cause: test fixtures use literal placeholder text like `"proposed"` as fake file content, which the linter correctly flags as invalid Python, triggering rollback. This is a test-fixture realism issue, not a production bug — flagged, not fixed, needs its own decision.

### `patchi/core/fix/risk_gate.py`
**Does:** Gates every patch before it touches disk — decides ALLOW_AUTO / REQUIRE_REVIEW / BLOCK. By design, never raises — always returns a decision.
**Depends on:** `patchi.core.config`, `patchi.core.memory`, `patchi.core.constants`
**Changes made this session:**
- Added `logging.getLogger("patchi.fix.risk_gate")`
- Logged config-load and brain-load failures (previously silent fallback to `{}` — dangerous because empty config could silently disable restricted-path protections)
- Logged `_get_mode()` fallback to `Mode.CONFIRM` (the fallback itself is correct/safest, just made visible)
- Did NOT change the "gate never raises" design contract — only added visibility into when fallbacks fire.

### `patchi/core/fix/fix_agents.py`
**Does:** 8 fix agents (CodeFixer, SecurityFixer, DeadCodeRemover, DependencyFixer, EnvFixer, TypeFixer, RefactorAgent, UnitTestRunner) — each calls AI once per finding, returns a Patch, never applies it directly.
**Depends on:** `patchi.core.agents.base`, `patchi.core.ai.client`, `patchi.core.fix.patch`
**Note:** File uses CRLF line endings — edited via Python script for byte-exact precision rather than str_replace.
**Changes made this session:**
- Added `logging.getLogger("patchi.fix.fix_agents")`
- Logged 4x audit-trail write failures (ai_call logging for CodeFixer/finding path, DependencyFixer, RefactorAgent, UnitTestRunner) — previously silent.

---

## Key Decisions

- Web (`patchi/web`) is explicitly excluded from this fix pass per user direction — CLI/core only.
- Not blindly trusting the existing `AUDIT_STUBS_PLACEHOLDERS_WRONG_LOGIC.md` — verifying each claim against actual code before treating it as true.
- Fixing silent exceptions in ordered batches by directory, verified with `py_compile` + relevant pytest run after each batch, not as one giant blind pass.
- When a fix reveals a deeper bug (like the mkdir issue), fixing it inline if it's small/safe/directly connected — not silently expanding scope without flagging it.

---

### `patchi/core/security/` — 35 files, 95 instances
**Method:** AST-based (not regex/manual) — parsed each file to find exact enclosing class/function for every bare `except Exception:`, so every log message names the real method that failed (e.g. `"DefenseLayer._exec_block_ip failed: %s"`) instead of a generic message.
**Severity rule used:** `warning` by default (a silent scan/probe failure in a security tool = a false negative dressed up as a clean result — that's the dangerous case). `debug` only for the 2 genuine format-detection-try instances in `domain_loader.py` (`_try_load_yaml`).
**Bug introduced then caught by own verification (reporting honestly, not hiding it):** the automated script's logic for finding "where the import block ends" inserted the new `_log = ...` line between a decorator (`@register`, `@dataclass`) and the class/function it decorates, which is invalid Python — broke 21 of 35 files. Caught immediately by running `py_compile` on all 35 files right after (not just assuming success). Root cause fixed (decorator-aware insertion), all 21 corrected, full re-verification confirmed 35/35 compile clean.
**Test result:** 174 passed, 1 skipped, 0 failed — `tests/` filtered to security-relevant modules (web/integration tests excluded, separate scope, blocked on missing `fastapi` until installed this session).
**High-stakes file called out specifically:** `defense_layer.py` — the 6 fixes there cover active defense actions (block IP, invalidate session, suspend account, block WS origin, update dependency, log defense result). If these silently failed before, the system could report "defended" when no defensive action actually happened. All 6 now warn loudly on failure.

**Side-check performed (per user request, not part of the exception-logging task):** Verified Playwright is a real, working dependency — not a stub. `playwright>=1.40` declared in `pyproject.toml`, installed (1.56.0), Chromium binary confirmed to actually launch. `browser_tester.py` genuinely drives a real browser (`sync_playwright()` → `chromium.launch()` → real `page.goto()`/`query_selector_all()` calls) for auth-bypass/XSS/SQLi form testing — confirmed via direct code read, not assumption. Caveat flagged to user: `pip install playwright` alone doesn't download the browser binary — `playwright install chromium` is a separate required step, worth confirming it's in the project's setup docs/README.

### `patchi/cli/` — 24 files, 59 instances
**Method:** same AST-based approach as security/, with two script bugs found and fixed mid-batch (both caught by compile-checking every file immediately, not trusting the script's exit code):
1. **Decorator-adjacent insertion (repeat of the security/ bug)** — avoided this time by fixing the script before running, not after.
2. **New bug: text-based `.lstrip()` scanning matched an indented `def` inside a `try/except ImportError` fallback block as if it were a top-level definition** (`init.py`'s `except ImportError: def draw_logo(): ...` pattern), corrupting that file's import fallback structure. Fixed by switching entirely to `tree.body` (AST top-level statements only — structurally cannot match nested defs) instead of text scanning. Restored all 24 files to original and re-ran clean with the fixed script rather than patching just the one broken file.
**CRLF:** 18 of 24 files were CRLF. Explicit integrity check run after this batch (not assumed) — confirmed 0 files had their line endings altered, unlike the one miss in the security/ batch.
**Severity rule used:** `warning` by default (silent failure in a user-facing CLI = command "succeeds" while quietly doing less than it claims). `debug` only for 3 genuine optional-local-service probes: `_check_ollama`, `_ping_model` (model_cmd.py), `_test_ollama` (doctor_cmd.py) — Ollama not running locally is a normal, frequent, non-error condition for most users, not a real problem to warn about.
**Test result — verified as true apples-to-apples:** ran the full suite (`pytest tests/`, web/integration excluded) on both the edited code and a fresh copy of the original unedited code, same command, same scope. Both: **18 failed, 1334 passed, 2 skipped** — identical. (An earlier partial-file comparison briefly suggested one new failure; re-checking with a full-suite-vs-full-suite comparison instead of full-vs-subset showed it was test-order pollution in the existing suite, not caused by this batch — isolated re-run of that one test passed cleanly on its own.)

**Full pre-existing test failure inventory (none touched this session, flagged for your awareness/prioritization):**
- `test_applier.py` (5) — test fixtures use non-code placeholder text that trips the linter; not a production bug (see core/fix section above)
- `test_detector.py::TestEWMAMeter` (2) — `test_sees_outliers`, `test_warmup_and_mean` — not yet investigated
- `test_new_features.py::TestKeyWebAPI` (8) — key management web API tests, all failing — not yet investigated, web-adjacent so may be lower priority given CLI-only scope
- `test_scanners.py::TestTestScanner::test_uncovered_files_flagged` (1) — not yet investigated
- `test_test_agents.py::test_all_test_agents_registered` — flaky/order-dependent only, passes in isolation, not a real bug

## Side Addition — `p cockpit` (Live Session Dashboard)

User-provided package (`patchi_cockpit.zip`, with its own `INTEGRATION.md`) integrated this session. Not part of the exception-logging project — a genuinely new feature, verified rather than assumed to work.

**Files added:**
- `patchi/core/brain/cockpit.py` (new) — data layer: gathers health/drift/fixes/blast-radius/secrets signals that already exist elsewhere in Patchi; adds no new analysis of its own.
- `patchi/cli/commands/cockpit_cmd.py` (new) — Rich-based TUI rendering, matches existing ant-colony color convention.
- `patchi/cli/main.py` (edited) — 3 integration points: command factory (`_cmd_cockpit`), subparser (`p_cockpit`, flags `--area`/`--interval`/`--poll`/`--once`/`--scan-secrets`), dispatch (`elif cmd == "cockpit"`).

**Verification performed before trusting the integration doc's claims (same standard as everywhere else this session):**
- Confirmed all 5 claimed dependencies (`health.compute`, `audit.compute_drift`, `proactive.build_fix_list`/`rank_fixes`, `reasoning.ReasoningEngine.impact_analysis`, `secrets.scan_secrets`) genuinely exist with matching function signatures AND matching field/dict-key names (`HealthScore.total/.grade/.color`, `ProposedFix.fix_type/.file/.name/.description/.safe`, `ImpactAnalysis.affected_layers/.impacted_layers/.summary`, `SecretHit.path/.line/.rule`, `compute_drift`'s dict keys `has_plan`/`clean`/`scope_diff`/`new_findings`) — all matched exactly. This package was accurately built against the real codebase.
- Added logging to 5 silent `except Exception:` blocks in the new `cockpit.py` before integrating it — inconsistent to add fresh silent-swallow code into a codebase this session has been actively cleaning up. `debug` level for the 3 "no brain yet" gatherers (expected/frequent, would spam logs on every fresh-project refresh otherwise); `warning` for blast-radius and secrets-sweep (per-save, more likely a real problem — secrets-sweep failing silently is exactly the "false sense of security" pattern flagged in the `core/security` batch).

**Bug hit during integration (reported honestly):** hand-typed Unicode box-drawing/em-dash separators in the `main.py` anchor text didn't exactly match the file (typed `─` U+2500 where the file used `—` U+2014 in "learn — detect"). Assertion caught it before any write happened — nothing was corrupted. Fixed by extracting all anchor text directly from the file instead of retyping it, eliminating the whole class of transcription error.

**Real bug found via actual end-to-end testing (not just compiling) — this is the significant one:** `p cockpit --once` (documented as "CI / smoke test") hung indefinitely on this real project. Root cause, confirmed by isolating and timing each pipeline stage individually rather than guessing:
- `patchi/core/brain/proactive.py`'s `_check_dead_code` re-read every other file from disk for every candidate symbol in every file — O(files² × symbols_per_file) disk reads. Fixed with a shared read-cache (verified: same output, correctness-preserving, since file content is static during one scan).
- Caching alone wasn't enough — the deeper cost is `_word_in_source`'s regex search still running up to ~2.3M times on this project (4351 candidate symbols × up to 530 other files each). This is a genuine O(n²) algorithmic issue in the dead-code detection engine itself (no pre-indexed identifier table), and a full fix has real correctness nuance (the existing regex deliberately excludes attribute-access matches like `obj.name` from counting as a reference to top-level `name` — a naive tokenization rewrite would silently change dead-code detection behavior). **Not fixed** — flagged clearly as its own future task rather than rushed under time pressure inside a cockpit-integration step.
- **What was fixed, scoped to the cockpit's own responsibility:** `gather_full()` no longer forces an unbounded synchronous fix-list computation for `--once`. It now reuses the existing background-thread mechanism (`refresh_fixes_async`, already lock-protected) and does a *bounded* `.join(timeout=12s)` wait. Small/scoped projects still get the full fix list in one frame exactly as designed; large whole-project scans render on time with a clear "still computing, scope with --area" message instead of hanging forever.

**Actually run and observed, not assumed:**
- `p cockpit --once` (whole project): completes in 12s (the bound), health 80/B rendered correctly, graceful "still computing" message shown.
- `p cockpit --once --area patchi/core/fix` (scoped): completes in 9s, shows real Prioritized Fix List data (23 findings).
- `p cockpit --once --area patchi/core/fix --scan-secrets`: secrets sweep runs and reports findings.

**Known quirk flagged, not fixed (separate scope):** the secrets sweep flagged 21 hits inside `patchi/core/security/playbooks/*.yaml` — almost certainly false positives, since those are the security scanner's own pattern-documentation files, not real secrets. Likely a missing directory exclusion in `secrets.scan_secrets`, not a cockpit bug.

### `patchi/core/agents/` — 20 files, 54 instances
**Method:** same proven AST-based script (decorator-aware, `tree.body`-only top-level detection, CRLF normalize/restore) — zero script bugs this time, clean on first pass.
**Severity rule used:** `warning` by default — same reasoning as `core/security`: a silent scanner-agent failure is a false negative dressed up as a clean scan, and `Coordinator` is the orchestration hub running every agent, so a silent failure there could mean a whole group of agents silently didn't run. 9 exceptions classified `debug`, each checked individually for a genuine "safe to degrade silently" pattern rather than assumed:
- 4x tree-sitter AST node-accessor helpers (`_ts_node_text`, `_ts_child_by_field`, `_ts_children`, `_ts_node_type` in `duplicate_scanner.py`) + `_node_text_buf` (`route_graph_scanner.py`) — low-level parsing helpers where occasional failure on unusual syntax is expected, not a scan-level problem.
- `_get_git_churn`, `_parse_lcov`, `_parse_coverage_json` (`coverage_prioritizer.py`) — best-effort heuristics for an optional, nice-to-have coverage-prioritization ranking, not a security-relevant check; degrading silently here doesn't hide a real problem.
- `Coordinator._maybe_reorder` — an agent-run-order optimization that already falls back to the original order on any failure; the fallback is 100% correctness-preserving, just potentially less efficient.
**Consistency callback:** `Coordinator.__init__`'s config/brain-load fallback (lines 100, 106) is the exact same pattern already fixed in `risk_gate.py` during the `core/fix` batch — classified `warning` to match, for the same reason (silent fallback to empty config/brain could quietly change gating/orchestration behavior).
**Verification:** all 20 files compile clean, decorator-adjacency check clean, CRLF integrity confirmed (10 of 20 files were CRLF, all preserved), 0 remaining bare exceptions. Full test suite: **18 failed / 1334 passed / 2 skipped — identical to the established baseline**, zero regressions.

### `patchi/core/testing/` — 12 files, 22 instances
**Method:** same proven script, clean on first pass again (3rd batch in a row with no script bugs, now that the decorator/CRLF/nested-def issues are all fixed for good).
**Severity rule used:** `warning` by default — a silent failure in a test-running agent is the same "false clean result" risk as everywhere else (e.g. visual regression's hash cache failing silently means every run looks like a "first run," never actually detecting a real visual change). 3 classified `debug`, each checked individually:
- `_parse_sitemap` (`accessibility_agent.py`) — code already had an explicit comment ("If XML parsing fails, return empty list") marking this as intentionally optional.
- `_emit` (`live_test_runner.py`) — only affects the live WebSocket event stream for the UI, not the actual test results or their persistence (`_save_results` is separate and correctly kept at `warning`).
- `_is_api_contract` (`api_contract_agent.py`) — a detection heuristic ("is this file a contract file, yes/no") feeding a larger scan, not the contract validation itself.
**Consistency callback:** `test_config.py`'s `load()` config-fallback is the same pattern as `risk_gate.py` and `Coordinator.__init__` — kept `warning` to match.
**Verification:** 12/12 compile clean, decorator check clean, 0 remaining bare exceptions, 3 debug / 19 warning split confirmed exactly as planned. Full test suite: **18 failed / 1334 passed / 2 skipped — identical baseline**, zero regressions.

### `patchi/core/*.py` root, `detector`, `hosted`, `ai`, `notifications` — 8 files, 16 instances
**Method:** same proven script for 7 uniform-line-ending files. One file (`patchi/core/detector/sigma_engine.py`) had genuinely mixed CRLF/LF line endings within itself (pre-existing, not caused by anything this session) — handled with a separate, precise byte-level edit that touched only the exact target lines rather than risk normalizing the whole file to one style.
**Real catch mid-edit:** `sigma_engine.py` already had its own logger, just named `logger` instead of the `_log` convention used everywhere else. Caught before finalizing (would have left two differently-named loggers in the same file) — used the file's own existing name instead of forcing the usual convention on it.
**Severity rule used:** `warning` across all 16 — every single instance in this batch was a core state/audit function (`memory.py`'s health-history and rejection-count tracking, `audit_log.py`'s `write()` — literally the audit trail itself, `ip_reputation.py`'s reputation-DB load where silent failure means every IP check would pass by default, `client.py`'s `_call_ai_horde` matching the exact same "silently returns None on any failure" pattern already found in `security_probe.py`). No genuine "safe to degrade silently" case among these, unlike previous batches.
**Verification:** all 8 compile clean, decorator check clean, CRLF integrity confirmed on the 7 uniform files, `sigma_engine.py`'s mixed pattern confirmed undisturbed outside the 1 intentional edit. Full test suite: **18 failed / 1334 passed / 2 skipped — identical baseline**, zero regressions.

**Honest note on how the `core/brain` miss happened:** the very first breakdown in this session (before any batch work started) correctly listed `core/brain` at 164. When `BUILD_MAP.md` was created immediately after, that row was dropped from the tracked table — an actual transcription mistake, not a deliberate scoping choice. Every batch since then was checked against the (incomplete) table, so nothing caught it until this final project-wide `grep` swept all of `core/` + `cli/` directly instead of trusting the tracker. Lesson for next time: verify the tracker's total against a fresh full-project count periodically, not just at the start.

### `patchi/core/brain/` (+ `type_checker/`, `route_detector/`, `ast_utils/`) — 43 files, 164 instances — the largest single batch
**Method:** same proven script, zero script bugs (4th clean batch in a row now that the CRLF/decorator/nested-def issues were fixed for good early on). `brain.py` already had its own logger named `logger` (not `_log`) — special-cased to use the file's existing name rather than force the usual convention on it, same lesson as `sigma_engine.py` earlier.
**Severity rule used:** `debug` reserved strictly for the established "low-level AST/tree-sitter node-accessor helper" pattern (`_ast_text`, `_node_text`, `_ts_node_text`, etc. — same functions/pattern as `core/agents`, some of them literally the same function name in a different file) plus `git_aware.py`'s `_git`/`_blame_one` (matches the `coverage_prioritizer.py` git-enrichment precedent). Everything else — all 9-language `symbol_graph.py` walkers/extractors, all 7-language `route_detector` auth-annotation checks, all `scanner.py` language parsers, `Brain.scan` itself, `domain_activator.py`'s `activate_domains` (directly relevant to the domain-taxonomy conversation earlier this session), `audit.py`'s drift computation, `contract.py`'s `_call_ollama`/`_call_openai_compat` (same pattern already found twice elsewhere) — defaults to `warning`, since this directory is almost entirely detection/state-correctness code where a silent failure means a real gap in coverage, not a cosmetic issue.
**Verification:** all 43 files compile clean, decorator check clean, 0 remaining bare exceptions. Full test suite: **18 failed / 1334 passed / 2 skipped — identical baseline held**, zero regressions, despite this being by far the most foundational code touched all session (42 fixes alone in `symbol_graph.py`, the cross-language symbol-extraction engine everything else depends on).
**Real end-to-end smoke test, not just unit tests:** ran `p scan` against this actual project. Completed successfully (exit 0). Actually *observed* the new logging working live in the output — an AI-backend call failure (expected: this sandbox's network egress blocks that domain) printed instead of vanishing silently, which is the entire point of this project made visible in a real run rather than just inferred from tests.

## What's Next (genuinely remaining)

- [x] ~~Old-style agent signature migration~~ — DONE (all agents now use `_run(inp, result) -> None`)
- [x] ~~Pre-existing test failures~~ — DONE (1573 passed, 3 skipped, 0 failures)
- [x] ~~Domain/playbook reset~~ — DONE (334 domains, 335 playbooks, 335 fix-playbooks, 17 Sigma rules)
- [x] ~~CLI hang in non-TTY~~ — FIXED: `scan_cmd.py` now checks `con.is_terminal` and skips `Rich.Live` when not in TTY. Also capped `annotate_findings_with_blame` at 200 findings per agent to avoid excessive `git blame` subprocess calls on Windows.
- [ ] Secrets scan flags playbook YAML files as false-positive secrets (missing directory exclusion)
- [ ] DomainLoader._load_all() takes ~22s for 334 domains — may need caching for test speed

## Retrospective — the whole 424-instance project

Six batches, one real tracking mistake (caught and corrected transparently — `core/brain` dropped from the tracker after batch 1, found via a final full-project sweep rather than trusted batch arithmetic), a handful of real script bugs along the way (decorator-adjacent insertion, a text-scanner mistaking a nested `def` for a top-level one, CRLF line-ending flattening) — every one caught by verifying rather than assuming, and fixed before moving on rather than patched around. Test suite held at the exact same 18 failed / 1334 passed baseline through every single batch. Along the way this also caught two real, independent bugs unrelated to the exception-logging task itself: a rollback-status bug in `applier.py` that could report `rolled_back=True` even when rollback failed, and an O(n²) performance bug in `proactive.py`'s dead-code checker that made `p cockpit --once` hang indefinitely.
