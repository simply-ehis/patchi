# Patchi — Linking Pass & Dependency Resolution Spec (Part 3)

**This is a prerequisite, not a parallel workstream.** Do this before Part 2 §3
(the AI harness) and before any of the "testing jobs" improvements discussed
alongside these specs. A smarter AI or a nicer report sitting behind
disconnected commands and silently-missing tools doesn't help — it just adds
polish to a system that doesn't reliably run its own features.

Two separate problems, found by tracing actual code paths, not by inspection alone:
1. **Broken connections** — real, well-built features that nothing in the CLI
   ever calls.
2. **Dependency gap** — no reliable way to know which external tools an agent
   needs, whether they're installed, or how to install them. When they're
   missing, agents silently produce nothing instead of saying so.

---

## 0. Non-Negotiable Rules (same as prior specs)

1. Extend, don't rebuild.
2. No half-fixes — if linking one command surfaces a second broken assumption,
   fix that too in the same pass.
3. Every "done" needs evidence.
4. No flag-gated forks of core functionality (Part 2 §1 already covers Governor;
   this rule applies to whatever else the audit in §1 below turns up).

---

## 1. The Linking Pass — Find Every Orphaned Component

### Confirmed examples (proof of the pattern, not the full list)

- **`DASTAgent` (`core/security/dast_agent.py`, 865 lines, fully built) is only
  ever instantiated from two web dashboard routes** (`web/api/scan.py`,
  `web/routes/assurance.py`). It is never called from `p scan`, `p ready`,
  `p test`, or the Governor pipeline. A CLI user gets zero value from it,
  despite it being real, working code.
- **`p ready`'s security step is a hardcoded 3-agent shortlist** (`BanditAgent`,
  `SemgrepAgent`, `CatchBlockAuditor` — by name, in `cli/commands/ready_cmd.py`),
  not the actual `AgentGroup.SECURITY` group. The other ~122 registered security
  agents never run as part of "ship readiness," and neither Bandit nor Semgrep
  is installed by default (see §2) — so this step is frequently a near-total no-op
  that still reports as having run.
- **`p security` is documented in the README as a command family but doesn't
  exist in the actual CLI** — running it returns `invalid choice: 'security'`.
  The real subcommands (`findings`, `chains`, `rules`, etc.) exist individually,
  but the umbrella command described in the docs does not.
- **Dead code created by the fork in Part 2 §1**: `scan_cmd.py` line 626 builds
  `_sec_names = {a.name for a in _la(AgentGroup.SECURITY)}` and only acts on it
  `if _sec_agents:` — but in the non-`--governor` path, `AgentGroup.SECURITY`
  never ran, so `_sec_agents` is always empty and this block can never fire.
  Merging Governor into base `p scan` (Part 2 §1) fixes this one as a side
  effect — flagged here so it's on the list, not treated as a new separate bug.

### What to do
This needs a systematic audit, not just fixing the four examples above:

1. **Enumerate every registered agent** (anything using `@register` in
   `core/agents/`, `core/security/`, `core/testing/`).
2. **For each one, trace whether it's reachable from an actual CLI command** —
   either because its `AgentGroup` is dispatched by a command the user can run
   today, or because it's referenced by name somewhere in `cli/commands/`.
   "Registered" is not "reachable" — `DASTAgent` was registered and still orphaned.
3. **Anything reachable only from `web/`** gets flagged as CLI-orphaned. Per the
   README's own stated design (*"1:1 CLI ↔ Web — the web is a fancy wrapper;
   every screen maps to a command"*), this is a direct violation of the
   project's own stated architecture, not a matter of opinion.
4. **Anything documented in README/`COMMANDS.md` that doesn't exist in the real
   CLI** (like `p security`) gets fixed in whichever direction is correct — either
   build the missing command or correct the docs. Don't leave the mismatch.
5. Produce this audit as an actual artifact (a checklist or table), not just a
   pass/fail — this becomes the tracking document for closing each gap, and
   the next person (human or agent) working on this shouldn't have to redo
   the trace.

---

## 2. The Dependency Gap — One Real Tool Registry, Detection, and Install Path

### The exact problem, in code
`core/agents/tool_health.py` is the only tool-availability checker wired into
the CLI (`p doctor`), and its entire registry is:
```python
_TOOLS = frozenset({
    "bandit", "semgrep", "codeql", "pyre", "safety", "pip-audit",
    "git", "node", "npm", "ollama",
})
```
But grepping the actual codebase for tools agents depend on turns up at least
these **additional** tools that `p doctor` never checks for at all: `gitleaks`,
`osv-scanner`, `httpx`, `nuclei`, `sqlmap`, `dalfox`, `ffuf`, `zap`, `shannon`.
None of these are pre-installed by `pip install patchi` (they're separate
binaries/npx packages) — I confirmed a fresh install has none of them present.

On top of that, there's a **second, separate, narrower tool-check system**
(`core/security/tool_verify.py`) that only knows about `bandit` and `semgrep`,
hardcoded, used specifically for the post-fix verification loop. It doesn't
share a registry with `tool_health.py` — two different places independently
decide "is this tool available," with different tool lists.

The practical effect: an agent that depends on a missing tool (say, `GitleaksAgent`
depending on `gitleaks`, or `PentestRegistry.run("sqlmap", ...)` when `sqlmap`
isn't installed) either errors somewhere downstream, or — worse, per the pattern
from Part 2 — silently returns zero findings that look identical to "ran and
found nothing." There is no consistent, visible "this check did not run because
X is missing" signal anywhere in the reports.

### What to do

1. **One tool registry**, covering every external tool actually referenced
   anywhere in the codebase (start from the full list above; audit for more
   during the linking pass in §1, since new orphaned features may depend on
   tools not yet listed anywhere). `tool_verify.py` should call into this
   registry instead of hardcoding its own two-tool list.
2. **Every entry needs an install hint**, not just a status. Most of these have
   a real one-liner: `pip install bandit`, `pip install semgrep`,
   `npm install -g gitleaks` or the Go install command, `go install
   github.com/google/osv-scanner/cmd/osv-scanner@latest`, `npx nuclei`, etc.
   `_BROKEN_HINTS` in `tool_health.py` currently only covers 2 of 10 tools —
   extend this to cover every tool in the new unified registry, missing or broken.
3. **Surface this clearly and completely in `p doctor` / `p status`** — every
   tool the current project's config could plausibly use, whether it's present,
   and the exact install command if not. Not just the 10 that happen to be
   checked today.
4. **Add a real install path**, not just a hint to copy-paste. At minimum,
   `p doctor --install` (or similar) that attempts the pip/npm-installable ones
   automatically and clearly reports what it can't install for you (binaries
   needing a package manager, Docker, etc.) with the manual command to run.
5. **Every agent must report "skipped: tool missing" as its own distinct
   status**, not silently produce an empty findings list. This connects directly
   to Part 2 §2's honesty fixes — "0 findings because nothing was wrong" and
   "0 findings because the tool that would have found it isn't installed" are
   different facts and must never look the same in a report or affect a health
   score the same way.
6. **Playwright browsers are a special case worth calling out** — `pip install
   playwright` does not install the browser binaries; `playwright install` is a
   separate required step. `browser_pool.py` already has a good error hint for
   this (line 106) — confirm it's actually triggered reliably and that every
   Playwright-dependent agent (DAST, visual regression, browser testing) hits
   this same check consistently, not just the ones that happen to call
   `browser_pool.py` directly.

---

## 3. Acceptance Check for This Whole Spec

Before calling this done:
- Run `p doctor` (or its successor) on a completely fresh install with zero
  external tools present. It must list every tool the current project setup
  could use, mark all of them missing, and give a real install command for each.
- Install two or three of the easy ones (e.g. `bandit`, `semgrep`) and confirm
  `p doctor` correctly flips them to installed — the detection has to actually
  work both ways, not just report "missing" by default.
- Run `p ready` and confirm the security step now reflects real coverage
  (either the full security group, or an explicit accurate statement of what
  subset ran and why), not the old hardcoded 3-name list.
- Confirm `DASTAgent` fires from a CLI command when a live URL is available,
  not just from the web dashboard.

---

## Sequencing Across All Three Specs

1. **This spec (Part 3)** — link the orphaned pieces, close the dependency gap.
   Do this first, per your own call — no point wiring smarter behavior into
   commands that can't reliably reach their own features or tools yet.
2. **Part 2, §1–2** — merge Governor into base `p scan`, fix the honesty bugs.
3. **Part 1** — the confidence-gate calibration and standing eval set.
4. **Part 2, §3** — the actual AI harness (scoped context, structured I/O).
5. The professional-testing-tool improvements (authorization gate before active
   pentest tools, client-ready reporting, charter/scope enforcement on DAST) —
   these depend on §1–4 above already being solid, since they're about trusting
   and presenting results the earlier stages produce.
