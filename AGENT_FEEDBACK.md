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
