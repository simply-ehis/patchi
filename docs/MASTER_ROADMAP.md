# Patchi — Master Roadmap & Honest Sizing (updated for context handoff)

> Read this first in a new session. This is the single source of truth for what's done, what's
> left, and how big each remaining thing honestly is. Companion docs, all in `patchi_plans/`:
> `PATCHI_PLAN_v0.8.md` (detailed decision log, section-by-section, if you want the full story
> behind any item below), `LINKAGE_GUIDE.md` (what to also touch when editing X so it doesn't
> break Y — read before making cross-cutting changes), `debugger-delegation-brief.md` and
> `domain-reset-delegation-brief.md` (ready-to-send prompts for separate delegated work, neither
> started yet as of this handoff).

## How sizing works here

No fake hour estimates. Every item is sized **relative to real work already done and verified**,
so the scale means something:

| Size | Reference point |
|---|---|
| **XS** | The Scala parser fix — one function, one dispatch line |
| **S** | The C# route detector — one new file, two integration points, full pipeline verified |
| **M** | The CLI Theme system — three files, a real precedence bug found and fixed |
| **L** | One Command Unification batch (7–22 commands, each with real handler-signature verification) |
| **XL** | One exception-fixing batch like `core/security` — 95 instances, 35 files |
| **XXL** | The entire 424-instance exception project — the largest single body of work this session |

## Already done — the full list, for whoever picks this up next

- **424/424 silent exceptions fixed and verified** across 7 batches, full project-wide `grep`
  confirmed 0 remaining, zero regressions held through every batch.
- **Cockpit (`p cockpit`) integrated directly into the tree** — `core/brain/cockpit.py`,
  `cli/commands/cockpit_cmd.py`, wired into `main.py`. A real O(n²) performance bug was found and
  partially fixed in `proactive.py`'s dead-code checker along the way (caching added; the deeper
  algorithmic fix is still open, see below).
- **Command Unification (§3): framework built, 37 of ~49 commands migrated** across 4 batches.
  `patchi/cli/framework.py` + `patchi/cli/registry.py` are the core; `main.py`'s legacy ladder
  shrinks with each batch. Two real framework capabilities added along the way:
  `Arg(global_flag=True)` (for commands reading top-level flags like `--verbose`) and
  `Command(fixed_kwargs=...)` (for subcommands sharing one handler with a different hardcoded
  value each, e.g. `restrict add`/`scan-only`/`sensitive`). **11 real drift bugs found and fixed**
  across the whole migration — every single one caught by checking the actual handler function
  signature rather than trusting the parser's attribute name. Full list of what's migrated vs.
  still on the legacy ladder is in the Command Unification section below.
- **CLI Theme (§2) built and wired** — `themes.py` (4 palettes), `console.py`
  (`configure_theme()`), `style.py` (semantic helpers). A real precedence bug was found and fixed
  (an explicit `--theme` flag would have let ANSI codes leak into `--json` output — fixed so
  `--json` always wins, deliberately deviating from the source design doc's stated order).
- **Language expansion**: verified ~half of the original 10-phase plan already done before this
  session even started (Phases 0, 2, 3, 4, 6). Built the missing C# route detector this session
  (plus the ASP.NET Core framework-detection piece it depended on — a route detector with no
  framework detection is dead code, found that the hard way). Fixed a real gap where Scala fell
  through to a no-op parser instead of the intentional regex fallback the plan calls for.
- **mypy CI crash fixed** — three data directories with invalid Python package names were
  crashing mypy before it analyzed any real code; added a `pyproject.toml` exclude. Deliberately
  did NOT flip `|| true` to blocking — 309 pre-existing findings mean that's a real decision for
  a human, not something to change unilaterally.
- **Dead code cleanup** — leftover `elif cmd == "queue"/"key"/"patch"` blocks with dangling
  references to already-deleted functions, found via the mypy fix above, removed.
- **`ci-truth-serum` evaluated and not adopted** (disproportionate for how simple Patchi's actual
  CI is) — but evaluating it properly surfaced the mypy crash and the dead code above, both real.
- **Domain-reset delegation brief drafted** (`domain-reset-delegation-brief.md`) — for rebuilding
  the security domain/playbook taxonomy from open standards. **Blocked on the user's corrected
  upload** (a naming-mismatch issue in the existing playbook files needs resolving first).
- **Debugger delegation brief drafted and refined** (`debugger-delegation-brief.md`) — scoped as
  a Python-first, test-failure-triggered runtime context capture (not a general interactive
  debugger), feeding richer context into the existing fix-agent pipeline. Reuses existing DAP
  adapters (`debugpy`, confirmed standalone-capable); the DAP *client* genuinely needs building
  (confirmed no solid existing library). **Not started — brief is ready to send whenever.**
- **New gap found and logged, not started**: 42 security controls in the domain taxonomy are
  tagged `check_method: "dynamic"` (require runtime probing to verify — DAST territory, like
  OWASP ZAP) with **zero actual implementation**. Real architectural overlap with the debugger
  work: both need a "launch and manage a running process" primitive. Noted in the debugger brief
  to build that piece reusably, without scope-creeping the current delegation to cover both.
- **`LINKAGE_GUIDE.md` written** — the "if you touch X, also touch Y or it breaks silently" cross
  reference for this codebase, built from real couplings hit this session (the C# route detector
  needing framework detection, the domain/playbook filename contract, the `if lang == Lang.X`
  dispatch-chain pattern repeated across three separate files, the mode/auto-approval mechanism,
  and a real correction of an earlier wrong assumption about `queue.py`'s actual role).

## Command Unification — exactly what's left

**Migrated (37):** `init`, `health`, `status`, `doctor`, `watch`, `scan`, `cockpit`, `queue`,
`patch`, `key`, `fix`, `review`, `undo`, `redo`, `rollback`, `ask`, `why`, `impact`, `auto`,
`verify`, `mode`, `chat`, `dev`, `deps`, `explain`, `blast`, `brain`, `trend`, `blame`, `log`,
`update`, `learn`, `agents`, `model`, `memory`, `plan`, `restrict`.

**Still on the legacy ladder (12), each needing something beyond a plain registry entry:**
- `settings`, `access` — their "show"/list logic is written *inline* in `main.py`'s dispatch,
  not in a separate handler function. Needs extracting that logic into a real function in the
  command module first (small, real code change, not just registry work).
- `report` — converts a subcommand name into boolean flags before calling one handler. Needs a
  small wrapper in `report_cmd.py`, same pattern as the `mode_cmd.py` wrapper already built.
- `audit` — has non-trivial `--plan`-flag-changes-which-other-flags-get-read branching. Needs a
  closer look before deciding the right shape.
- `test`, `security`, `notify`, `web`, `ai`, `hosted`, `cross-repo` (7) — all pass either a raw
  positional value through hand-rolled `if/elif` in `main.py`, or the whole `args` object to one
  self-routing function. Different dispatch shape than this framework currently models. Needs
  either a framework extension or restructuring these commands' internals — deliberately not
  forced under time pressure across 4 batches now.
- `help` — tied to argparse internals (re-invokes the parser with different argv), not a normal
  command module. Probably stays on the legacy ladder permanently, or gets special-cased.

## What else is left, honestly sized

### CLI Theme (§2) — system built, adoption is the remaining work
Sweeping 1243 raw `print()` calls to the new helpers: **XL–XXL, or ongoing/never "done."**
Explicitly incremental per the design doc — pick high-traffic commands per session.

### Scan Bus (§1) — not started, the biggest single remaining item
`FileCorpus` (parse-once) + `safe_rglob` shim: **XL**, real blast radius confirmed **62 files**,
not the 19 the original design doc claims. Shards + `QueueRunner` + `FindingBus`: **XL–XXL**,
new architecture, correctness-critical. **Honest total: likely bigger than the entire
424-exception project.** Multiple dedicated sessions, not one.

### CI/PR bundle — not started, depends on Scan Bus + Command Unification's exit-code contract
Foundation (Finding model + stable id + renderer registry): **M**. Baseline+delta (`#1`, highest
leverage, already has a real primitive to build on — `compute_drift`): **M**. `--since`: **M**,
better with Scan Bus done first. CI gate + SARIF: **S each**. `p fix --safe-all`: **M**.

### New tool integrations — mechanical, no blockers, can run any time
Each new tool (ESLint, Bandit, etc.) following `tool_runner.py`'s existing pattern: **S each**.

### Dynamic security checks / DAST — new gap, not started
42 tagged controls, zero implementation. Depends on the same process-launch primitive the
debugger work needs — natural to sequence after that lands, or build the shared primitive first
if this becomes the priority instead.

### Debugger — brief ready, not started
Design work is done (the brief itself). Build is **L–XL**, scoped tight (Python-only first,
test-failure-triggered, no GUI). Ready to hand off whenever.

### Language expansion remainder
Phase 1 remainder (`_parse_html` → tree-sitter, fallback-vs-strict decision for 6 languages):
**S–M**. Phases 5, 7, 8, 9, 10: **genuinely unknown** — never given the same direct-code
verification pass the other phases got. Don't trust a guess here; check first.

### Domain reset — blocked on the user
Brief is ready. Sizing unknown until scope is set (how many standards, how deep).

### Cleanup / technical debt — no dependencies, slot in anywhere
35 legacy agent signature migrations: **M**. 309 mypy findings: **unknown until triaged** (never
looked past the count). 16 pre-existing failing tests, never investigated: **S to triage,
unknown to fix**.

## Honest bottom line, unchanged from the original version of this doc

Scan Bus and the unverified language-expansion phases remain the two real unknowns — both
plausibly bigger than anything completed so far. Everything else is either well-understood scope
or explicitly blocked on a decision only the user can make. If picking up fresh: Command
Unification's remaining 12 are genuinely the hard tail (diminishing returns per command now) —
reasonable to call that migration "done enough" and move to the CI/PR bundle foundation or Scan
Bus, rather than grinding out the last 12 for their own sake.
