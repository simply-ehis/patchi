"""Verify p web project resolution is 1:1 with other CLI commands."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from patchi.cli.commands.web_cmd import _resolve_project  # noqa: E402

base = Path(__file__).resolve().parent.parent / ".par_test"
if base.exists():
    import shutil

    shutil.rmtree(base)

proj = base / "projA" / "src"
proj.mkdir(parents=True)
(proj.parent / ".patchi").mkdir()
other = base / "other"
other.mkdir()
(other / ".patchi").mkdir()
empty = base / "empty"
empty.mkdir()

os.chdir(proj)
got = _resolve_project(None)
assert got == (base / "projA"), f"subdir should map to projA, got {got}"
print("PASS  inside-project/subdir -> nearest ancestor .patchi")

got = _resolve_project(str(other))
assert got == other.resolve(), f"explicit override failed: {got}"
print("PASS  explicit --project overrides")

# Scenario 3: refusal path. find_project_root() is SHARED by all commands
# (and this machine legitimately has ~/.patchi, so a real walk-up would find
# home). We monkeypatch it to None to exercise web_cmd's own refusal contract.
import tempfile  # noqa: E402

import patchi.core.config as _cfg  # noqa: E402

outside_empty = Path(tempfile.mkdtemp(prefix="par_no_project_"))
os.chdir(outside_empty)
orig = _cfg.find_project_root
_cfg.find_project_root = lambda start=None: None
raised = False
try:
    _resolve_project(None)
except SystemExit as e:
    raised = True
    assert e.code == 1, f"exit code {e.code}, want 1"
finally:
    os.chdir(Path(__file__).resolve().parent.parent.parent)
    _cfg.find_project_root = orig
    import shutil as _sh

    _sh.rmtree(outside_empty, ignore_errors=True)
assert raised, "_resolve_project should refuse with SystemExit(1) when no project up-tree"
print("PASS  refuses when no project up-tree (same as every other command)")

import shutil  # noqa: E402

shutil.rmtree(base, ignore_errors=True)
print("ALL RESOLUTION SCENARIOS PASS")
