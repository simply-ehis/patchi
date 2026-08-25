"""
Verify Loop — apply → re-run the failing test → retry → never weaken tests.

Reconstructed module (the original was lost before any commit existed;
this build follows the exact call contract in cli/commands/fix_cmd.py):

    outcome = run_verify_loop(patch, root=r, config=config, brain=brain,
                              applier=applier, log=callable)
    outcome.review_required   # patch only touches tests -> human must review
    outcome.applied           # final state applied
    outcome.verified          # the originally-failing test now passes
    outcome.retries_used      # number of RETRIES after the first attempt
    outcome.reason            # why it failed / could not be verified

Honesty rules carried over from the fix_cmd contract:
  - A patch whose changes are exclusively in test files is NEVER applied
    automatically (test-weakening guard) — flagged for human review.
  - Verification means the specific failing test passes again, not just
    "the applier said ok".
"""

from __future__ import annotations

import fnmatch
import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("patchi.fix.verify_loop")

MAX_RETRIES = 2  # attempts after the first one ("up to 2 retries")
_VERIFY_TIMEOUT_S = 120  # per-attempt cap for the targeted test re-run

_TEST_FILE_PATTERNS = (
    "test_*.py",
    "*_test.py",
    "conftest.py",
    "*.spec.ts",
    "*.spec.tsx",
    "*.spec.js",
    "*.spec.jsx",
    "*.test.ts",
    "*.test.tsx",
    "*.test.js",
    "*.test.jsx",
    "*_test.go",
    "*_test.rb",
    "*Test.java",
    "*Test.kt",
    "*Tests.swift",
)

_TEST_DIR_MARKERS = ("test", "tests", "spec", "specs", "__tests__", "testing")


def is_test_path(path: str) -> bool:
    """True if a relative path points into test code."""
    import posixpath

    p = path.replace("\\", "/")
    name = posixpath.basename(p)
    if any(fnmatch.fnmatch(name, pat) for pat in _TEST_FILE_PATTERNS):
        return True
    dirs = {seg.lower() for seg in posixpath.dirname(p).split("/") if seg}
    return bool(dirs & set(_TEST_DIR_MARKERS))


def should_flag_for_review(patch) -> bool:
    """Test-weakening guard: only-test-file patches always need a human."""
    changes = getattr(patch, "changes", None) or []
    if not changes:
        return False
    return all(is_test_path(getattr(c, "path", "")) for c in changes)


@dataclass
class VerifyOutcome:
    """Result of one fix → verify → retry campaign."""

    applied: bool = False
    verified: bool = False
    review_required: bool = False
    patch: object | None = None
    reason: str = ""
    retries_used: int = 0


def _rerun_failing_test(
    root: Path,
    test_file: str,
    log=None,
) -> tuple[bool, str]:
    """Independently re-run one test file. Returns (passed, tail_of_output)."""
    tf = Path(test_file)
    target = tf if tf.is_absolute() else root / tf
    if not target.is_file():
        return False, f"cannot re-run: {test_file} not found"
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
            [sys.executable, "-m", "pytest", "-x", "-q", str(target)],
            capture_output=True,
            text=True,
            timeout=_VERIFY_TIMEOUT_S,
            cwd=str(root),
        )
        tail = (proc.stdout or "").strip().splitlines()[-6:]
        output = " | ".join(tail)[:300]
        passed = proc.returncode == 0
        if log:
            log(f"re-ran {test_file}: {'PASS' if passed else 'FAIL'}")
        return passed, output
    except subprocess.TimeoutExpired:
        return False, f"test re-run timed out after {_VERIFY_TIMEOUT_S}s"
    except OSError as exc:
        return False, f"could not launch test runner: {exc}"


def recheck_test_file(root: Path, test_file: str) -> dict:
    """Re-run one previously-verified test file (REVERIFY phase helper).

    Contract used by governor._recheck_applied_patches:
      {"passed": True}   — test ran and passed
      {"passed": False}  — test ran and failed (regression)
      {"passed": None}   — could not run (file missing, runner error, timeout)
    Always includes "output" (tail of runner output) and "error" (message).
    """
    if not test_file or not is_test_path(test_file):
        return {"passed": None, "output": "", "error": f"not a runnable test path: {test_file}"}

    passed, output = _rerun_failing_test(Path(root), test_file)
    if "cannot re-run" in output or "could not launch" in output or "timed out" in output:
        return {"passed": None, "output": output, "error": output}
    return {"passed": bool(passed), "output": output, "error": "" if passed else output}


def run_verify_loop(
    patch,
    root: Path,
    config: dict | None = None,
    brain=None,
    applier=None,
    log=None,
) -> VerifyOutcome:
    """Apply *patch*, re-verify the failing test, retry up to MAX_RETRIES.

    Never raises: every failure mode becomes an honest VerifyOutcome.
    """
    say = log or (lambda _msg: None)

    # Guard first: test-only patches go to a human, full stop.
    if should_flag_for_review(patch):
        return VerifyOutcome(review_required=True, patch=patch)

    if applier is None:
        from patchi.core.fix.applier import PatchApplier

        applier = PatchApplier(root)

    source_finding = getattr(patch, "source_finding", {}) or {}
    test_file = source_finding.get("file", "")

    attempts = 1 + MAX_RETRIES
    last_reason = ""

    for attempt in range(1, attempts + 1):
        result = applier.apply(patch)  # never raises; rolls back on its own

        if not getattr(result, "success", False):
            last_reason = getattr(result, "error", "") or "apply failed"
            say(f"attempt {attempt}/{attempts} failed to apply: {last_reason}")
            patch.verify_retries = attempt - 1
            continue

        # Applied — now prove it: the original failing test must pass.
        if test_file and is_test_path(test_file):
            passed, detail = _rerun_failing_test(Path(root), test_file, log=say)
            verified = passed
            reason = "" if passed else f"verification failed: {detail}"
        else:
            verified = bool(getattr(result, "test_passed", False))
            reason = "" if verified else "applied but applier-level tests did not pass"

        if verified:
            patch.verify_retries = attempt - 1
            return VerifyOutcome(
                applied=True,
                verified=True,
                patch=patch,
                retries_used=attempt - 1,
            )

        last_reason = reason
        say(f"attempt {attempt}/{attempts} applied but unverified: {reason}")
        patch.verify_retries = attempt - 1

    return VerifyOutcome(
        applied=False,
        verified=False,
        patch=patch,
        reason=last_reason or "exhausted retries",
        retries_used=min(MAX_RETRIES, attempts - 1),
    )
