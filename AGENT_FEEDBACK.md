# AGENT_FEEDBACK.md — Patchi v2.0 Upgrade Session

## 2026-08-25 — Patchi v2 upgrade session

### ENV-01: Domain taxonomy data files incomplete in this checkout
- **Symptom:** `tests/test_domain_loader.py::TestPackagedDataIntegrity` expects
  `len(loader._domains) >= 300` and every control to have a playbook, but this
  checkout (`Patchi_COMPLETE`) ships only **48** domain YAMLs under
  `patchi/core/security/domains/` and **20** playbooks under `fix-playbooks/`.
  3 tests fail with e.g. `assert 48 >= 300`.
- **Root cause:** Data files were not fully exported/copied into this repo copy.
  The loader code itself works (it parses whatever YAMLs exist).
- **Impact:** 3 pre-existing test failures unrelated to v2 work.
- **Fix needed (human):** Re-copy the full `domains/*.yaml` + `fix-playbooks/*.yaml`
  set from the original machine/backup into `patchi/core/security/`.

### ENV-02: Full pytest suite exceeds single-command timeouts
- The suite (~77 files, 1500+ tests) takes >15 min on this machine.
- Workaround used: run in two halves via an args file
  (`pytest "@%TEMP%\pytest_half1.txt"`).
- Consider adding a `[tool.pytest.ini_options] addopts = "-m 'not slow'"` default
  or splitting CI jobs.

### Fixed during session (pre-existing bugs found by the suite)
- `ast_utils/scan.py`: Python call names were leaf-only (`execute`) instead of
  full dotted paths (`a.b.c.execute`) — now uses the shared `_py_call_name`
  helper as its docstring always intended.
- `ast_utils/assignments.py`: attribute targets (`config.debug = True`) and
  annotated assignments (`x: int = 5`) were silently skipped — now handled via
  `_py_assign_target_name`, plus AnnAssign support.
- `fix/verify_loop.py`: governor imported `recheck_test_file` which did not
  exist anywhere — implemented per the call contract in
  `governor._recheck_applied_patches` and the mocks in `test_governor_v2.py`.

### ENV-03: Concurrent external writes to this repo (IMPORTANT)
- **Symptom:** Files reverted/rewritten mid-session multiple times:
  `constants.py` lost AI_HORDE_* constants (20:04), `dashboard_v2.py` and
  `web_cmd.py` + templates reverted to pre-merge state (20:27), while
  `registry.py`, `app.py` kept newer content - leaving mismatched pairs that
  crashed (`p web` args vs archived stub).
  New externally-authored modules also appeared mid-session
  (`ai/tools/realize.py`, `routes/live_testing.py`, `routes/self_improvement.py`,
  `api/cicd.py`, `api/assurance*`, tenant router).
- **Impact:** Verification flip-flopped between runs; several broken imports
  and 500s traced to these partial reverts, not to merge code.
- **Likely cause:** Another agent/editor session or a file-sync tool running
  against this directory simultaneously.
- **Recommendation:** Close other sessions/sync before further changes; this
  session's final state was verified green AFTER the last observed revert.

### Fixed during verification round 2
- registry.py `learning` command: `args=Arg(...)` single value instead of
  tuple -> argparse build crash for EVERY CLI invocation.
- api/cicd.py called nonexistent `mem.load_scan_results` -> `get_scan_results`.
- routes/self_improvement.py 500: profiler summary missing keys on empty
  state -> agent_profiler.get_profile_summary now returns full key set.
- POST /api/hosted/init duplicate definition (legacy shadowed module API)
  -> legacy copy removed, canonical one in api/hosted.py.
- /live-testing page had invalid TemplateResponse signature (never worked)
  -> now redirects to unified /live-tests.

### Deep web audit round (user-requested ultra scan)
New tooling: `tools/deep_audit_web.py` - validates every href/fetch/static-ref
across all templates+JS against the live route table, template existence,
WS action coverage, JS DOM-ID contract, full render sweep, and a LIVE
multi-project discover->switch->verify cycle. Run after any UI change.

### Fixed in this round
- PERF: GET /api/security/report ran ALL security agents synchronously per
  request (measured 174s). Now cached-first from memory (0.1s); ?fresh=1
  opts into a live run; empty cache returns instant empty payload.
- Missing endpoint: POST /api/fix/apply-all-safe (button existed in
  review.html, route did not). Implemented via RiskGate: applies only
  ALLOW_AUTO patches; BLOCK/REVIEW are skipped and reported.
- Multi-project: added TenantManager.discover_projects() (bounded scan of
  parent/sibling dirs for .patchi), GET /api/tenant/discover, project
  switcher dropdown in the dashboard header wired to /api/tenant/list +
  switch + reload, and `p web --project <path>` flag with smart resolution:
  ancestor .patchi -> single child-of-cwd workspace pattern -> error listing
  candidates.
- Hardened POST /api/tenant/switch: refuses paths without .patchi unless
  init=true explicitly passed (previously would create .patchi inside ANY
  directory handed to it).
- Council page now calls real REST endpoint POST /api/v2/council/deliberate;
  sessions persist to memory so history renders (was calling nonexistent
  window.PATCHI_WS and never persisted).
- Mode selector JS posted to nonexistent /api/config/set -> fixed to legacy
  POST /api/config contract.
