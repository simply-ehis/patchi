# Patchi — Master Plan v0.8 (revised, reconciled with actual codebase)

> Supersedes the v0.7 plan written in OpenCode. That version assumed a frozen tree with
> standalone drop-ins; this session worked directly in the real `patchi/` tree instead, so this
> revision reconciles the plan with what's actually true on disk, verified directly rather than
> assumed.

## 0. What changed since v0.7 was written

- **§6 "Core hardening: kill 27 silent `except:`" — DONE, and the real number was 424, not 27.**
  Fixed across 7 batches this session (`core/fix`, `core/security`, `cli`, `core/agents`,
  `core/testing`, 5 small dirs, `core/brain`). Verified with a fresh project-wide `grep`, not
  batch arithmetic — 0 remaining. Full test suite held at an identical 18 failed / 1334 passed
  baseline through every batch.
- **The Cockpit (from `patchi_cockpit/`) is integrated directly into the tree**, not left as a
  drop-in — `patchi/core/brain/cockpit.py` (new), `patchi/cli/commands/cockpit_cmd.py` (new),
  3 edits in `patchi/cli/main.py`. Verified working end-to-end (`p cockpit --once`, both
  whole-project and `--area`-scoped).
- **A real O(n²) performance bug was found and partially fixed** in
  `proactive.py`'s dead-code checker — caching added (real speedup, verified), but the deeper
  algorithmic fix (pre-indexed identifier table) is still open; flagged, not rushed.
- **A real logic bug was found and fixed** in `applier.py` — rollback failures used to be
  silently reported as `rolled_back=True` even when the rollback itself failed.
- **The domain/playbook reconciliation this plan's §2 already flagged as a "Phase 0 blocker"
  is being actively resolved** — a delegation brief for a from-scratch domain+playbook reset,
  sourced directly from open standards, is drafted and ready
  (`domain-reset-delegation-brief.md`), pending the user's corrected upload of the existing
  playbook naming.

## 1. Corrections to the v0.7 design docs (verified against the real codebase, not assumed)

| Doc | Claim | Verified reality | Verdict |
|---|---|---|---|
| Scan Bus | "0 agents read `inp.scope`" | 2 do: `sast_agent.py`, `security_config.py` | Overstated, not fatal — core idea still sound |
| Scan Bus | "19 scanner files" use `safe_rglob` | 62 files: agents/18, security/40, brain/2, fix/1, root/1 | Real migration blast radius is 3x the stated scope |
| CLI Theme | "1176 raw print vs 152 Rich" | Actual: 1243 vs 1197 (near-balanced) | Motivating stat is stale; theme is still worth building for consistency, just not urgency |
| Command Unification | main.py "1141 lines" | Actual: 1390 (grew from Cockpit integration) | Confirms the problem is real and growing with every new command added the old way |

None of these corrections kill any of the four designs. They do mean: Scan Bus needs a wider
verification pass than planned, CLI Theme is a quality investment rather than an emergency, and
Command Unification is validated by a very recent, very real example (see below).

## 2. Sequencing decision (my call, as asked)

**Started with Command Unification (§3) — first batch DONE, verified.**

Built `patchi/cli/framework.py` (Arg/Command dataclasses, parser builder, dispatcher —
lazy-import preserved via dotted handler strings, exactly as the design required) and
`patchi/cli/registry.py` (7 real commands migrated: `init`, `health`, `status`, `doctor`,
`watch`, `scan`, `cockpit` — chosen to cover every real shape in the CLI: zero-arg, one
positional, a global-flag passthrough, a duplicated-vs-global flag, and `scan`'s full
14-argument surface, the most complex command in the tree).

Wired as a compat shim in `main.py`: registry dispatch is tried first; anything not
registered falls through to the untouched legacy `if/elif` chain. The 7 migrated commands'
old factory functions, parser blocks, and elif entries were deleted (not left duplicated —
duplicate argparse subparser names would crash at startup), except `_cmd_status`'s factory,
which stays because a second call site (`p` with no command, defaults to showing status)
still needs it independent of the elif chain.

**One real drift bug caught during the build, exactly the class this design exists to
prevent:** `scan`'s `--file` flag stores under `args.file` in the parser but the handler
function expects a kwarg named `file_path` — the legacy dispatch papered over this with a
manual rename (`file_path=getattr(args, "file", None)`); my first registry draft missed it
and would have silently passed the wrong kwarg name. Caught by checking every migrated
command's actual handler signature before considering it done, not by assuming the parser's
attribute names.

**Verified, not assumed:** all 3 new/touched files compile clean; `p --help` shows all 7
registry commands alongside the untouched legacy ones; `health`, `status`, `doctor`, `scan`
(with real args), and `cockpit` (with real args) were each actually run and produced correct
real output; `charter` (deliberately left unmigrated) was run to confirm the legacy fallback
still works. Full test suite: **18 failed / 1334 passed / 2 skipped — identical baseline**,
zero regressions.

**Remaining for this design:** ~30 more commands still on the legacy ladder (`notify`, `web`,
`ai`, `hosted` deliberately deferred — see below — plus the rest of the simpler ones). Migrate
a few at a time per the design's own strategy.

### Batch 2 — subcommand trees (`queue`, `patch`, `key`)

Proved out the one part of the framework the first batch didn't touch: `Command.subcommands`.
All three chosen specifically to stress-test different subcommand shapes:
- `queue` — 4 no-arg subcommands + `mode` (a positional with `choices`), and a real "no
  subcommand given" default behavior (`p queue` bare shows the queue).
- `patch` — 3 subcommands all taking the same kind of positional ID.
- `key` — same shape as patch, but its "no subcommand" default is `run_add` (interactive add),
  not a status/list view — a genuinely different existing behavior, replicated exactly rather
  than assumed to match queue's pattern.

**Three more real drift bugs caught, each checked against the actual handler signature rather
than assumed from the parser's attribute name** (bringing the running total to 4, counting
`scan`'s `--file`/`file_path` from batch 1): `queue mode`'s positional was `mode_name` in the
parser but the handler wants `mode_str`; `patch`'s show/apply/reject subcommands used `id` but
the handlers want `patch_id`; `key`'s remove/test subcommands used `name` but the handlers want
`nickname`. Also discovered mid-build: **argparse forbids overriding `dest` on positional
arguments** (raises `ValueError` at parser-build time, confirmed by directly testing it, not
assumed) — fixed by making `Arg.resolved_dest()` and `_add_args()` aware of this, matching a
positional's actual parser name to its handler kwarg directly rather than trying to remap it.

**Deliberately NOT migrated:** `notify`, `web`, `ai`, `hosted`. These pass the whole argparse
`Namespace` to one self-routing function (e.g. `run_notify(args)`) instead of one handler per
subcommand — a different dispatch shape than this framework models. Left on the legacy ladder
rather than force a fit or extend the framework under time pressure.

**Also found and fixed, unrelated to the migration itself:** ~1191 stray double-carriage-return
byte sequences (`\r\r\n`) had accumulated in `main.py` across this session's earlier edit
rounds — cosmetic (Python's universal-newline handling meant it never caused an actual
functional problem; every compile check and test run passed both before and after), but sloppy.
Cleaned up and re-verified nothing changed functionally.

**Verified:** registry + framework changes tested in isolation first (three targeted resolution
checks: `queue mode multi`, `patch show <id>`, bare `key`) before touching `main.py` at all.
After the `main.py` surgery: compiles clean, `queue`/`patch list`/`key list` each actually run
with correct real output, `--help` renders all 10 registered commands correctly. Full test
suite: **18 failed / 1334 passed / 2 skipped — identical baseline**, zero regressions.

**Order after this:** CLI Theme (additive, low-risk, rides the new dispatcher) → Scan Bus
(highest ceiling, now-larger verification scope) → CI/PR bundle (depends on both) → new tool
integrations (mechanical, can run in parallel any time) → debugger gap (needs its own design
pass first — no existing design doc covers it, unlike the other four) → **language/framework
expansion (new, see §6 below)**.

## 3. The debugger gap (confirmed, not yet designed)

Confirmed directly: nothing in `core/testing/`, `core/brain/`, or anywhere else touched this
session is an actual interactive debugger (breakpoints, stepping, runtime inspection) — what
exists are test/scan agents, a different category of tool entirely. The tool-research document's
own conclusion matches: no good universal debugger exists; the right shape is DAP as an
integration layer with language-specific debuggers plugged in underneath (Delve for Go, LLDB/GDB
for compiled languages, debugpy for Python, etc.). This needs its own design doc, written with
the same rigor as the other four, before implementation — not started yet.

## 4. New tool integrations (mechanical, low-risk, can run any time)

`tool_runner.py` currently wires up exactly 3 tools (`gitleaks`, `semgrep`, `vulture`) following
a clean, consistent pattern: check-if-installed → subprocess → parse JSON → graceful
tool-missing fallback → logged failure (the last step added this session). Every new tool from
the research doc's Tier 1 list (Trivy, TruffleHog already-partially-covered-by-gitleaks, ESLint/
Biome for JS-TS, per-language type checkers) is mechanical, bounded work following that exact
existing pattern — no new architecture needed, just more functions shaped like the existing three.

## 5. Language/framework expansion — doc found, verified against real code

**The doc was in the original zip all along** (`_planning_docs/LANGUAGE_EXPANSION_PLAN.md`),
never actually a separate upload — found by fully exploring the zip's top-level structure for
the first time this session (also found `_planning_docs/` with 17 other planning/audit docs,
and `files-5/` with 4 more, never previously examined). 10-phase plan, ~62 days estimated,
goal: full tree-sitter AST parity across ~13 languages, zero regex source parsing.

**The headline finding: much of this plan is already built** — verified directly against the
real files, not assumed from the doc's own status claims (which read as if starting from zero):

| Phase | Plan's ask | Verified actual state |
|---|---|---|
| 0 — tree-sitter deps | Add PHP/C#/Kotlin/Dart | ✅ Done, and exceeded — Svelte/C/C++/Bash/CSS/SQL parsers also present, none requested by the plan |
| 1 — kill scanner.py regex | Replace regex parsers with tree-sitter, no fallback | 🟡 Partial — Java/Go/C++/Swift/Ruby/PHP already tree-sitter *primary* with regex only as a fallback safety net (better than the plan assumed, but not matching its stricter "no fallback" philosophy). `_parse_html` still stdlib `html.parser`, not tree-sitter. **Real bug found:** `_parse_generic` (meant to be deleted per the plan) is now a no-op `pass` — bash/CSS/SQL files get *zero* import/symbol extraction right now, which is worse than either the old regex or the plan's intended dedicated parsers. |
| 2 — multi-language import graph | Stop re-parsing with Python-only `ast.parse`, consume `FileInfo.imports` | ✅ Done — confirmed `build_graph` reads `fi.imports` directly, no `ast.parse` call anywhere in the file |
| 3 — type_checker/ | Create 10 per-language modules | ✅ Structurally complete — exactly the proposed file list exists, 913 lines of real logic (not stubs), TypeScript most mature at 243 lines |
| 4 — route_detector/ | Create 9 per-language modules | ✅ **Now fully complete** — `csharp.py` built and verified this session (see below); every other language already existed |
| 6 — ast_utils/ | Create 6 shared AST utilities | ✅ Structurally complete and extended — all 6 planned files present plus `dead_symbols.py`, `helpers.py`, `config.py` beyond the plan's own list |
| 5, 7, 8, 9, 10 | Symbol graph cleanup, fix-agent expansion, blast radius parity, test fixtures, docs/CI | Not yet verified this session |

**Correction to an earlier claim in this doc:** a prior pass through this session flagged
`_parse_generic`'s no-op body as an active regression supposedly affecting bash/CSS/SQL files.
That was wrong — checked too shallowly. Full trace of `scanner.py`'s dispatch chain shows
`_parse_bash`, `_parse_css`, `_parse_sql` are dispatched to directly (each a real, complete
tree-sitter implementation with a regex fallback), never falling through to `_parse_generic` at
all. The *actual* (much narrower) gap: `_parse_generic` is only still reached by Scala — which
the plan itself says should keep regex until a PyPI grammar ships, but currently gets nothing,
since there's no `elif lang == Lang.SCALA` branch routing it to a regex path at all — and by
genuinely unclassifiable files, where doing nothing is correct.

**C# route detector — built, wired, and verified this session, closing the one confirmed real
gap in route_detector/:**
- `patchi/core/brain/route_detector/csharp.py` (new) — ASP.NET Core attribute-based routing
  (`[HttpGet]`, `[Route]`, `[Authorize]`), tree-sitter primary with a regex fallback, matching
  the established pattern from `java.py`. Node types (`attribute`, `attribute_list`,
  `attribute_argument_list`, the `name` field on both `attribute` and `method_declaration`) were
  verified by actually parsing a real C# sample through the installed grammar first, not
  assumed from generic tree-sitter-c-sharp documentation.
- `patchi/core/brain/framework.py` — added `_detect_csharp`, the ASP.NET Core/`.csproj`
  equivalent of the existing `_detect_java`. This was a **second gap the route detector alone
  wouldn't have surfaced**: without framework detection recognizing ASP.NET Core at all, a
  perfectly correct C# route detector would still never actually run, since `route_mapper.py`
  only activates a language's detector when one of its mapped frameworks is detected as present.
- `patchi/core/brain/route_mapper.py` — added `"c_sharp": {"ASP.NET Core"}` to `_LANG_FW_MAP`
  and the corresponding detector registration, matching every other language's wiring exactly.
- **Verified with a real, complete pipeline run**, not just unit-level checks: built an actual
  throwaway ASP.NET project on disk (`.csproj` + a controller with GET/POST/DELETE routes, one
  with role-based `[Authorize]`), ran the real `FileScanner` → `FrameworkDetector` →
  `RouteMapper` chain against it end to end. Correct output: ASP.NET Core detected at 0.95
  confidence, all 3 routes extracted with correct paths (class-level `[Route]` prefix correctly
  combined with method-level suffixes), correct handlers, and correct per-route auth detection.
- Full test suite after all of this: **18 failed / 1334 passed / 2 skipped — identical
  baseline**, zero regressions.

**Still open:** Scala's regex-fallback gap (small, bounded — needs one `elif` branch and a
`_parse_scala_regex` function, following the `_parse_bash_regex` pattern), `_parse_html`
conversion to tree-sitter, and the tree-sitter-primary-vs-strict-no-fallback philosophy decision
for the six languages that currently keep a regex safety net.

## 6. CLI Theme (§2) — built and verified this session

Built the full theme system from `DESIGN_cli_theme.md`: `patchi/cli/themes.py` (4 palettes —
`dark`, `light`, `mono`, `highcontrast` — each mapping the same 17-token semantic set to Rich
styles plus a matching symbol set), extended `patchi/cli/console.py` with `configure_theme()`
(runtime palette selection, additive — `con` still works unchanged for anyone who never calls
it), and `patchi/cli/style.py` (semantic one-liner helpers: `ok()`, `warn()`, `err()`, `heading()`,
`grade()`, `severity()`, `kv()`).

**Real finding worth noting: `config.py` already had a top-level `"theme": "dark"` default** —
used `"dark"` as the actual default palette name (not the design doc's generic `"default"`) to
match what's already there, avoiding yet another config-value-vs-code-key mismatch.

**One real precedence bug found and fixed, deviating deliberately from the design doc's literal
order:** the doc ranks explicit `--theme` above `--json`/non-TTY forcing mono. Tested that
literally and found it means `--json --theme dark` would leak ANSI codes into JSON output —
correctness bug, not just an aesthetic one, since it'd silently break downstream JSON parsers.
Fixed by ranking `--json` first, unconditionally, above even an explicit theme choice, and
documented why directly in `resolve_palette_name()`'s docstring rather than silently deviating
from the source design.

**Verified:** all four palettes construct AND render without error (real render test, not just
construction — some invalid Rich color names only fail at render time). Full real CLI
invocations (`p health`, `p health --theme mono`, `p --theme mono health`) — including catching
that `--theme` placed *after* the subcommand fails, then confirming that's a pre-existing
argparse/subparser limitation shared by every other global flag (`--verbose` has the identical
issue), not something this feature introduced. Confirmed the `--json`-forces-mono fix through
the actual dispatch path (`_build_parser()` + real arg parsing), not just the isolated function.
Full test suite: **18 failed / 1334 passed / 2 skipped — identical baseline**, zero regressions.

**Not yet done:** the actual sweep of 1243 raw `print()` calls to the new helpers — this session
built the system and wired it into dispatch, but migrating call sites is explicitly incremental
per the design doc ("not a blocking rewrite"), high-traffic commands first (scan, security,
health, status, audit).

## 7. External tool evaluated: `ci-truth-serum` — verdict: not adopted, but it surfaced two real bugs

User linked https://github.com/AlexanderMattTurner/ci-truth-serum (a pre-commit hook pack that
catches CI pipelines lying about their own results — exit-code masking, stderr suppression,
unpinned base images, etc.) and asked whether it's needed.

**Verdict: don't adopt the tool.** Checked its ~20 checks against Patchi's actual
`.github/workflows/ci.yml` (one file, two simple jobs, no Dockerfiles, no `decide-job +
always()` gating architecture) rather than judging generically. Nearly all of Tier 2
(opinionated, architecture-specific) and the identity checks don't apply — there's nothing here
for them to find. Installing a whole hook pack for a project this CI-simple would be
disproportionate tooling overhead.

**But evaluating it directly surfaced two real, unrelated bugs, found by actually checking
instead of dismissing the whole thing on the disproportionate-fit verdict alone:**

1. **`mypy patchi/ --ignore-missing-imports || true` in the CI workflow doesn't just suppress
   findings — mypy currently *crashes* before analyzing anything** (exit code 2), because
   `fix-playbooks/`, `playbooks/`, and `domains/` each carry a stray `__init__.py` in a
   hyphenated directory name, which isn't a valid Python package name and breaks mypy's package
   discovery outright. `|| true` was hiding a total tooling failure, not just some type errors.
   **Fixed the crash** by adding a `[tool.mypy]` exclude in `pyproject.toml` for those three
   data directories (they were never meant to be type-checked — they hold YAML, not code).
   Verified mypy now actually runs: exit code 1 (309 real findings) instead of exit code 2
   (crash before checking anything). **Deliberately did NOT remove `|| true`** — 309 pre-existing
   type errors mean flipping that to blocking would immediately break CI on the next push. That's
   a consequential call for the user to make once those errors are triaged, not something to
   change unilaterally.

2. **With the crash fixed, mypy's real output caught genuine dead code**: `main.py` still had
   the old `elif cmd == "queue"/"key"/"patch":` blocks from before the Command Unification
   migration, referencing `_cmd_queue`/`_cmd_key`/`_cmd_patch` — factory functions deleted during
   that migration. Currently harmless (registry-first dispatch always intercepts these three
   commands before legacy code is ever reached — confirmed with real command runs, both before
   and after this fix), but genuine dangling references that would crash the moment that
   short-circuit ever changed. Missed during the original migration cleanup; removed now.

**Self-caught, worth noting honestly:** while first checking mypy's exit code with `--exclude`
applied, piped through `| tail -30`, the *displayed* exit code was actually `tail`'s, not
mypy's (`$?` after a pipe captures the last command in it) — showing exit 0 when the real
mypy exit code was 1. Re-ran without the pipe to get the true code. A live example of exactly
the failure class `ci-truth-serum`'s `check-workflow-pipefail` targets, caught mid-investigation
of that very tool.

Full test suite after all three fixes: **18 failed / 1334 passed / 2 skipped — identical
baseline**, zero regressions.

## 8. Command Unification — Batch 3 (22 more commands, 32 total migrated)

Following the Master Roadmap's own recommendation (finish Command Unification before Scan Bus).
Migrated: `fix`, `review`, `undo`, `redo`, `rollback`, `ask`, `why`, `impact`, `auto`, `verify`,
`mode`, `chat`, `dev`, `deps`, `explain`, `blast`, `brain`, `trend`, `blame`, `log`, `update`,
`learn`. Deferred `test`/`security` alongside the already-deferred `notify`/`web`/`ai`/`hosted`
— they hand-roll if/elif branching on a positional value directly in `main.py`'s dispatch
rather than using real argparse subparsers, the same "different dispatch shape" reasoning as
before. Also deferred `cross-repo` — confirmed it passes the whole `args` object to one
self-routing function, exactly the notify/web/ai/hosted pattern.

**Added a small wrapper (`run()`) to `mode_cmd.py` itself** — the only genuine module-level
change this batch, not just registry/framework work. `mode`'s existing `run_show`/`run_set`
were two separate functions with main.py doing the "no arg = show, arg given = set" branching;
the framework needs one handler per Command, so the branching moved into the module as a small,
reusable wrapper rather than being forced to fit awkwardly elsewhere.

**7 more drift bugs found and fixed this batch (running total: 11 across the whole migration)**,
every one caught by checking the actual handler signature rather than trusting the parser's
attribute name: `undo`/`redo`/`rollback`'s `id` → handlers want `patch_id`; `explain`'s `--type`
→ handler wants `finding_type`; `blast`'s `--all` → handler wants `show_all`.

**One real process failure, worth stating plainly rather than glossing over:** claimed all
factory reference counts "matched expectations" before removing them, by pattern-matching
`_cmd_update`'s count against the already-verified `undo`/`reason` cases instead of actually
checking its specific call sites. It has two, both **outside** the elif dispatch chain
entirely — a background weekly update-check thread and a post-dispatch update notification,
neither visible from the elif block itself. Running the real CLI immediately surfaced this as a
`NameError` on `p mode`, `p ask`, `p undo`, `p blast`, `p trend` — everything downstream of that
code path. Fixed by importing `auto_check_background`/`print_update_available_if_needed`
directly rather than through the deleted factory, verified by re-running every affected command.

**Also caught mid-verification:** `verify`'s parser call is split across multiple lines in the
source (`sub.add_parser(\n    "verify", ...\n)`), which an earlier single-line grep missed
entirely — the first registry draft registered `verify` with zero args, dropping its real
`--no-scan`/`--claim` flags. Caught by cross-checking add_argument counts per command against
the registry before touching `main.py`, not assumed correct because it compiled.

**Verified:** all 22 commands' arg counts cross-checked against the registry before any removal
(not just spot-checked); all deferred commands' parsers and elif blocks confirmed still intact
after the removal pass; real CLI runs for a representative sample including every drift-fixed
flag, all producing correct real output; `p test unit` (deferred, legacy path) confirmed still
working; full test suite: **18 failed / 1334 passed / 2 skipped — identical baseline**, zero
regressions despite this being the largest single migration batch by command count.

**Remaining:** `test`, `security`, `notify`, `web`, `ai`, `hosted`, `cross-repo` (7 commands,
all needing either a framework extension for the self-routing pattern, or restructuring their
internal dispatch into real argparse subparsers) plus roughly 8 simpler ones not yet checked
(`restrict`, `settings`, `access`, `agents`, `report`, `model`, `memory`, `audit`, `plan`,
`help`) — some of which have subcommands per the earlier reconnaissance and haven't had their
handler signatures verified yet.

## 9. New gap found: dynamic security checks — 42 controls tagged, zero implemented

User asked why Patchi doesn't run code for deeper checking, given it already fixes/scans/tests.
Checked directly rather than answering from intuition: **42 controls across the security domain
taxonomy are tagged `check_method: "dynamic"`** (meaning verifiable only by actually running the
target and probing it — classic DAST territory), **and none of them have any actual runtime
implementation** — the one `dynamic` string match in `core/fix/fix_agents.py` turned out to be
unrelated (dead-code reference checking, not security probing).

This isn't "add execution from zero" — Patchi already runs code in several narrow, purpose-built
ways (test agents run pytest/Playwright, `tool_runner.py` runs Semgrep/Gitleaks/Vulture,
`applier.py` reruns tests to verify a fix). What's missing specifically is *launch the target,
then actively probe it with crafted input* — exactly what OWASP ZAP does, already scored highly
(18/20) in this session's earlier tool research but never actually integrated.

**Real architectural connection to the debugger work**: both this and the debugger delegation
need the same underlying primitive — launch and manage a running process. Added a note to the
debugger delegation brief instructing whoever builds it to keep the process-launch code cleanly
separated from Python/debugpy-specific logic, so it's realistic to reuse for this dynamic-check
work later, without scope-creeping the current delegation to cover both.

**Status: identified and logged, not started.** A separate initiative from the debugger work,
tracked here so it isn't lost — likely its own future delegation brief once the debugger work
is further along, given the shared-primitive dependency.

## 10. Command Unification — Batch 4 (5 more commands, 37 total migrated)

`agents`, `model`, `memory`, `plan`, `restrict`. Added a genuinely new, reusable framework
capability this batch: `Command.fixed_kwargs` — for cases where several subcommands share one
underlying handler but each needs a different hardcoded value baked in (`restrict add`/
`scan-only`/`sensitive` all call the same `run_add(path, rtype, reason)`, only `rtype` differs
per subcommand). 8th drift fix this migration: `run_add`'s second parameter is `rtype`, not
`restriction_type` — caught the same way as the previous 7, checking the real signature instead
of guessing a sensible-sounding name.

**A real concern raised and resolved during this batch, worth documenting for its own sake:**
adding `restrict`'s fixed_kwargs required importing `RestrictionType` at `registry.py`'s module
level — which runs at parser-build time, on every single CLI invocation, seemingly working
against this framework's whole "nothing extra imports until dispatch resolves it" principle.
Measured it directly rather than assuming either way: `import patchi.core.constants` alone costs
~3ms; the ~300ms first measured was from importing the top-level `patchi` package itself, an
unavoidable cost `main.py` already pays just to run at all. Confirmed with real `p --help`
timing (settles to ~108ms after cache warm-up, same as before this batch) — no fix needed, but
worth the five minutes to verify rather than either ignore the concern or revert good work over
an unmeasured worry.

**Also hit the same multi-line `add_parser(...)` blind spot as `verify` earlier** — this time in
my own *verification* step (checking whether `audit`'s parser survived the `plan` removal), not
in a registry entry. `audit: 0` looked like a real deletion bug for a few minutes; turned out to
be the same grep limitation, confirmed by switching to a multi-line-aware regex. Nothing was
actually lost — but it's the second time this exact blind spot has caused a false alarm, worth
remembering for any future batch: always use a multi-line-aware check for `add_parser`
verification, not a single-line grep.

**Verified:** every factory's reference count checked individually this time (not pattern-matched
against a previous case, learning directly from the `_cmd_update` mistake in Batch 3) — all 5
had exactly 2 references, no hidden extra call sites. `fixed_kwargs` tested in isolation before
touching `main.py` (all 3 `restrict` variants resolved with the correct `rtype`). Real CLI runs
for all 5 commands, including `restrict add` with a real path/reason to confirm `fixed_kwargs`
actually works end-to-end (confirmed: correctly applied `NO_TOUCH`, then cleaned up the test
data). Full test suite: **18 failed / 1334 passed / 2 skipped — identical baseline**, zero
regressions.

**Remaining:** `settings`/`access` (inline logic in `main.py`, no separate handler function to
point to yet), `report` (subcommand→boolean conversion, needs a small wrapper like `mode_cmd.py`
got), `audit` (complex flag-branching), `test`/`security`/`notify`/`web`/`ai`/`hosted`/
`cross-repo` (7 commands, self-routing or hand-rolled dispatch shape), `help` (tied to argparse
internals, not a real command module) — 12 commands left on the legacy ladder.

## 11. Open items carried forward unchanged from v0.7

- Old-style agent signature migration (35 agents on the legacy pattern) — never started.
- Pre-existing test failures (`test_applier.py` x5, `test_detector.py` x2, `test_new_features.py`
  x8, `test_scanners.py` x1) — never touched, still open.
- `patchi_rules` (the separate offline rule-pack engine mentioned in v0.7 §2, "14/14 tests pass,
  dogfooded, 138 findings/330 files") lives outside this session's tree and hasn't been seen or
  verified here — flag as an integration dependency once it's brought into this tree.
