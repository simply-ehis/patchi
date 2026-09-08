"""
Patch applier for Patchi.

Applies a patch to disk:
1. Take snapshot of all files to be changed (via core.snapshot)
2. Write each FileChange.proposed to disk
3. Run relevant tests (scoped to changed files)
4. If tests fail → automatic rollback via snapshot
5. Update patch state and save to memory

Fix agents always run sequentially (one at a time — spec says non-negotiable).
The applier is synchronous and blocking. The coordinator calls it in a queue loop.

Test runner strategy (uses subprocess; dedicated test agents run full coverage):
  Python   → pytest [changed file path] --tb=short -q
  Node/TS  → npm test / jest [changed file pattern] --passWithNoTests
  No tests → skip test phase, warn user

Auto-rollback fires when:
  - Any test command exits with a non-zero code
  - Disk write fails midway (partial write safety)
  - Timeout exceeded (60s default)
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC
from pathlib import Path

from patchi.core import memory as mem
from patchi.core import snapshot as snap
from patchi.core.atomic import atomic_write_text
from patchi.core.fix.patch import Patch, PatchState

_log = logging.getLogger("patchi.fix.applier")

# ── Apply result ───────────────────────────────────────────────────────────────


@dataclass
class ApplyResult:
    patch_id: str
    success: bool
    rolled_back: bool = False
    snapshot_id: str = ""
    test_passed: bool | None = None  # None = no tests found
    test_output: str = ""
    lint_passed: bool | None = None  # None = no linter found
    lint_output: str = ""
    error: str = ""
    duration_ms: int = 0
    verify_status: str = "unverified"  # M-16: passed/failed/unverified
    verify_remaining: int = 0

    def to_dict(self) -> dict:
        return {
            "patch_id": self.patch_id,
            "success": self.success,
            "rolled_back": self.rolled_back,
            "snapshot_id": self.snapshot_id,
            "test_passed": self.test_passed,
            "test_output": self.test_output[:2000],  # cap output stored
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# ── Applier ────────────────────────────────────────────────────────────────────


class PatchApplier:
    """
    Applies a patch to disk with snapshot + auto-rollback.

    Usage:
        applier = PatchApplier(project_root)
        result = applier.apply(patch)
    """

    TEST_TIMEOUT = 60  # seconds

    def __init__(self, root: Path):
        self.root = root

    def apply(self, patch: Patch) -> ApplyResult:
        """Apply a patch. Returns ApplyResult. Never raises."""
        t0 = time.monotonic()

        # ── Policy gate check (WIRE-03) ────────────────────────────────────────
        try:
            from patchi.core.constants import RiskLevel
            from patchi.core.security.governance import patchi_action_log, patchi_policy_gate

            risk_sev = RiskLevel.from_score(patch.risk_score).value
            for change in patch.changes:
                allowed, reason = patchi_policy_gate(
                    self.root, "patch_apply", change.path, risk_sev
                )
                if not allowed:
                    patchi_action_log(
                        self.root, "patch_blocked", change.path, detail=reason, status="blocked"
                    )
                    return ApplyResult(
                        patch_id=patch.id,
                        success=False,
                        error=f"Policy gate blocked: {reason}",
                        duration_ms=_ms(t0),
                    )
        except ImportError:
            pass  # governance module unavailable — proceed

        # ── 1. Snapshot ────────────────────────────────────────────────────────
        try:
            snapshot_id = snap.create(patch.affected_paths, patch.id, self.root)
        except Exception as e:
            return ApplyResult(
                patch_id=patch.id,
                success=False,
                error=f"Snapshot failed: {e}",
                duration_ms=_ms(t0),
            )

        # ── 2. Write files ─────────────────────────────────────────────────────
        written: list[str] = []
        try:
            for change in patch.changes:
                # Policy gate check before writing (WIRE-03)
                try:
                    from patchi.core.security.governance import (
                        patchi_action_log,
                        patchi_policy_gate,
                    )

                    severity_str = (
                        "high"
                        if patch.risk_score >= 61
                        else "medium"
                        if patch.risk_score >= 31
                        else "low"
                    )
                    allowed, reason = patchi_policy_gate(
                        self.root, "patch_apply", change.path, severity_str
                    )
                    if not allowed:
                        snap.restore(snapshot_id, self.root)
                        return ApplyResult(
                            patch_id=patch.id,
                            success=False,
                            rolled_back=True,
                            snapshot_id=snapshot_id,
                            error=f"Policy gate blocked: {reason}",
                            duration_ms=_ms(t0),
                        )
                    patchi_action_log(
                        self.root,
                        "patch_apply",
                        change.path,
                        agent="PatchApplier",
                        detail=f"patch_id={patch.id}",
                    )
                except ImportError:
                    pass

                # Secrets gate check (NEW-02) — block patches introducing secrets
                try:
                    from patchi.core.security.secrets_guard import gate_check_proposed_code

                    if change.proposed:
                        safe, secret_findings = gate_check_proposed_code(
                            change.proposed, change.path
                        )
                        if not safe:
                            snap.restore(snapshot_id, self.root)
                            return ApplyResult(
                                patch_id=patch.id,
                                success=False,
                                rolled_back=True,
                                snapshot_id=snapshot_id,
                                error=f"Secrets gate blocked: proposed code in {change.path} introduces secrets",
                                duration_ms=_ms(t0),
                            )
                except ImportError:
                    pass

                abs_path = self.root / change.path
                if change.proposed == "":
                    # Empty proposed = deletion (DeadCodeRemover uses this)
                    if abs_path.exists():
                        abs_path.unlink()
                else:
                    atomic_write_text(abs_path, change.proposed)
                written.append(change.path)
        except Exception as e:
            # Partial write — rollback immediately
            rollback_ok = True
            try:
                snap.restore(snapshot_id, self.root)
            except Exception as rb_err:
                rollback_ok = False
                _log.warning(
                    "Rollback after failed write also failed (snapshot=%s): %s",
                    snapshot_id,
                    rb_err,
                )
            return ApplyResult(
                patch_id=patch.id,
                success=False,
                rolled_back=rollback_ok,
                snapshot_id=snapshot_id,
                error=(
                    f"Write failed after {len(written)} file(s): {e}"
                    + (
                        ""
                        if rollback_ok
                        else " (rollback ALSO failed — files may be in a partial state!)"
                    )
                ),
                duration_ms=_ms(t0),
            )

        # ── 3. Run tests ───────────────────────────────────────────────────────
        test_result = self._run_tests(patch.affected_paths)

        # ── 3b. Run linter ────────────────────────────────────────────────────
        lint_result = self._run_linter(patch.affected_paths)

        # ── 4. Rollback if tests or linter failed ─────────────────────────────
        failed = False
        failure_reason = ""
        if test_result["passed"] is False:
            failed = True
            failure_reason = "Tests failed"
        elif lint_result["passed"] is False:
            failed = True
            failure_reason = "Linter errors introduced"

        if failed:
            try:
                snap.restore(snapshot_id, self.root)
                rolled_back = True
            except Exception as rb_err:
                rolled_back = False
                test_result["rollback_error"] = str(rb_err)

            # Update patch state
            self._update_patch_state(patch.id, PatchState.FAILED, test_result, snapshot_id)

            return ApplyResult(
                patch_id=patch.id,
                success=False,
                rolled_back=rolled_back,
                snapshot_id=snapshot_id,
                test_passed=test_result.get("passed"),
                lint_passed=lint_result.get("passed"),
                test_output=test_result.get("output", ""),
                lint_output=lint_result.get("output", ""),
                error=f"{failure_reason}. {'Rolled back.' if rolled_back else 'Rollback also failed!'}",
                duration_ms=_ms(t0),
            )

        # ── 5. Verify fix (M-16: detect-fix-verify loop) ──────────────────────
        verify_result = self._verify_fix(patch)

        # ── 6. Success ─────────────────────────────────────────────────────────
        self._update_patch_state(patch.id, PatchState.APPLIED, test_result, snapshot_id)

        # Audit log for successful apply (WIRE-04)
        try:
            from patchi.core.security.governance import patchi_action_log

            targets = ", ".join(c.path for c in patch.changes[:5])
            patchi_action_log(self.root, "patch_applied", targets, detail=patch.id, status="ok")
        except Exception as e:
            _log.warning("Failed to write audit log entry for patch %s: %s", patch.id, e)

        # Mark brain stale (files changed)
        try:
            mem.mark_brain_stale(patch.affected_paths, self.root)
        except Exception as e:
            _log.warning("Failed to mark brain stale for patch %s: %s", patch.id, e)

        result = ApplyResult(
            patch_id=patch.id,
            success=True,
            rolled_back=False,
            snapshot_id=snapshot_id,
            test_passed=test_result.get("passed"),
            test_output=test_result.get("output", ""),
            duration_ms=_ms(t0),
        )
        result.verify_status = verify_result.get("status", "unverified")
        result.verify_remaining = verify_result.get("remaining", 0)
        return result

    def rollback(self, patch_id: str, snapshot_id: str) -> ApplyResult:
        """
        Manually rollback a previously applied patch.
        Used by `p undo [id]` and `p rollback [id]`.
        """
        t0 = time.monotonic()
        try:
            restored = snap.restore(snapshot_id, self.root)
            self._update_patch_state(patch_id, PatchState.ROLLED_BACK, {}, snapshot_id)
            mem.mark_brain_stale(restored, self.root)
            return ApplyResult(
                patch_id=patch_id,
                success=True,
                rolled_back=True,
                snapshot_id=snapshot_id,
                duration_ms=_ms(t0),
            )
        except Exception as e:
            return ApplyResult(
                patch_id=patch_id,
                success=False,
                error=f"Rollback failed: {e}",
                duration_ms=_ms(t0),
            )

    # ── Verify fix (MISS-15: detect-fix-verify loop) ───────────────────────────

    def _verify_fix(self, patch: Patch) -> dict:
        """Re-scan changed files to confirm the fix resolved the finding.

        Uses the original scanner agent (if known) for precise verification.
        Falls back to FileScanner complexity check for generic patches.
        """
        try:
            from patchi.core.agents.base import get_agent
            from patchi.core.brain.scanner import FileScanner

            # If we know which scanner agent found the issue, re-run it
            scanner_agent = patch.scanner_agent or patch.source_finding.get("agent", "")
            finding_type = patch.finding_id or patch.source_finding.get("type", "")
            finding_file = patch.source_finding.get("file", "")
            finding_line = patch.source_finding.get("line", 0)

            if scanner_agent and finding_type:
                agent_cls = get_agent(scanner_agent)
                if agent_cls:
                    from patchi.core.agents.base import AgentInput

                    inp = AgentInput(
                        root=self.root, scope=patch.affected_paths, brain={}, config={}
                    )
                    result = agent_cls().run(inp)
                    # Check if the same finding type still exists on the same file
                    still_present = any(
                        f.type == finding_type
                        and f.file == finding_file
                        and (finding_line == 0 or abs(f.line - finding_line) <= 3)
                        for f in result.findings
                    )
                    if not still_present:
                        return {"status": "passed", "remaining": 0}
                    patch.verify_retries = max(patch.verify_retries - 1, 0)
                    return {
                        "status": "failed",
                        "remaining": 1,
                        "can_retry": patch.verify_retries > 0,
                    }

            # Fallback: generic complexity check
            scanner = FileScanner(self.root)
            remaining = 0
            for change in patch.changes:
                abs_path = self.root / change.path
                if not abs_path.exists():
                    continue
                info = scanner.scan_file(abs_path)
                if info and info.complexity and info.complexity > 10:
                    remaining += 1
            if remaining == 0:
                return {"status": "passed", "remaining": 0}
            return {"status": "failed", "remaining": remaining}
        except Exception as e:
            _log.warning("Fix verification failed for patch %s: %s", patch.id, e)
            return {"status": "unverified", "remaining": -1}

    # ── Test runner ────────────────────────────────────────────────────────────

    def _run_tests(self, changed_paths: list[str]) -> dict:
        """
        Run relevant tests for the changed files.
        Returns {passed: bool|None, output: str, runner: str}
        """
        runner, cmd = self._detect_test_runner(changed_paths)
        if runner is None:
            return {"passed": None, "output": "No test runner detected.", "runner": None}

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self.root),
                timeout=self.TEST_TIMEOUT,
            )
            passed = proc.returncode == 0
            output = (proc.stdout + proc.stderr)[:3000]
            return {"passed": passed, "output": output, "runner": runner}
        except subprocess.TimeoutExpired:
            return {"passed": False, "output": "Tests timed out (60s).", "runner": runner}
        except Exception as e:
            return {"passed": None, "output": str(e), "runner": runner}

    def _detect_test_runner(self, changed_paths: list[str]) -> tuple[str | None, list[str]]:
        """
        Detect the test runner for the changed files.
        Returns (runner_name, command_list) or (None, []) if none found.
        """
        import shutil

        # Python: pytest — only if matching test files exist
        py_files = [p for p in changed_paths if p.endswith(".py")]
        if py_files and shutil.which("pytest"):
            test_files = self._find_python_tests(py_files)
            if test_files:
                return "pytest", ["pytest", "--tb=short", "-q"] + test_files

        # Node/TypeScript: jest or npm test
        js_files = [p for p in changed_paths if p.endswith((".js", ".ts", ".jsx", ".tsx"))]
        if js_files:
            if shutil.which("jest") and (self.root / "package.json").exists():
                try:
                    pkg = json.loads((self.root / "package.json").read_text())
                    if "jest" in str(pkg.get("devDependencies", {})):
                        pattern = "|".join(Path(p).stem for p in js_files[:3])
                        return "jest", [
                            "jest",
                            "--testPathPattern",
                            pattern or ".",
                            "--passWithNoTests",
                        ]
                except Exception as e:
                    _log.debug("Could not parse package.json for jest detection: %s", e)
            if (self.root / "package.json").exists() and shutil.which("npm"):
                try:
                    pkg = json.loads((self.root / "package.json").read_text())
                    if "test" in pkg.get("scripts", {}):
                        return "npm", ["npm", "test", "--", "--passWithNoTests"]
                except Exception as e:
                    _log.debug("Could not parse package.json for npm test detection: %s", e)

        return None, []

    def _find_python_tests(self, source_paths: list[str]) -> list[str]:
        """Find pytest test files corresponding to source files."""
        test_files: list[str] = []
        for src in source_paths:
            from pathlib import PurePosixPath

            stem = PurePosixPath(src).stem
            candidates = [
                f"tests/test_{stem}.py",
                f"tests/{stem}_test.py",
                f"test_{stem}.py",
                f"{PurePosixPath(src).parent}/test_{stem}.py",
                f"{PurePosixPath(src).parent}/tests/test_{stem}.py",
            ]
            for c in candidates:
                if (self.root / c).exists():
                    test_files.append(c)
        return test_files

    LINT_TIMEOUT = 30

    def _run_linter(self, changed_paths: list[str]) -> dict:
        """
        Run linter on changed files to catch introduced errors.
        Returns {passed: bool|None, output: str, linter: str}
        """
        import shutil

        py_files = [p for p in changed_paths if p.endswith(".py")]
        if py_files and shutil.which("ruff"):
            try:
                proc = subprocess.run(
                    ["ruff", "check", "--select=E,F,W"] + py_files,
                    capture_output=True,
                    text=True,
                    cwd=str(self.root),
                    timeout=self.LINT_TIMEOUT,
                )
                passed = proc.returncode == 0
                output = (proc.stdout + proc.stderr)[:2000]
                return {"passed": passed, "output": output, "linter": "ruff"}
            except subprocess.TimeoutExpired:
                return {"passed": None, "output": "Linter timed out.", "linter": "ruff"}
            except Exception as e:
                return {"passed": None, "output": str(e), "linter": "ruff"}

        js_files = [p for p in changed_paths if p.endswith((".js", ".ts", ".jsx", ".tsx"))]
        if js_files and shutil.which("npx"):
            try:
                proc = subprocess.run(
                    ["npx", "--yes", "eslint"] + js_files[:5],
                    capture_output=True,
                    text=True,
                    cwd=str(self.root),
                    timeout=self.LINT_TIMEOUT,
                )
                passed = proc.returncode == 0
                output = (proc.stdout + proc.stderr)[:2000]
                return {"passed": passed, "output": output, "linter": "eslint"}
            except subprocess.TimeoutExpired:
                return {"passed": None, "output": "Linter timed out.", "linter": "eslint"}
            except Exception as e:
                return {"passed": None, "output": str(e), "linter": "eslint"}

        return {"passed": None, "output": "No linter available.", "linter": None}

    # ── State updates ──────────────────────────────────────────────────────────

    def _update_patch_state(
        self,
        patch_id: str,
        state: PatchState,
        test_result: dict,
        snapshot_id: str,
    ) -> None:
        """Update patch state in memory."""
        try:
            from datetime import datetime

            from patchi.core import memory as mem

            patches = mem.list_patches(self.root)
            for patch in patches:
                if patch.get("id") == patch_id:
                    patch["state"] = state.value
                    patch["snapshot_id"] = snapshot_id
                    patch["test_result"] = test_result
                    now = datetime.now(UTC).isoformat()
                    if state == PatchState.APPLIED:
                        patch["applied_at"] = now
                    elif state == PatchState.FAILED:
                        patch["rolled_back_at"] = now
                    elif state == PatchState.ROLLED_BACK:
                        patch["rolled_back_at"] = now
                    break

            # Save back — need to write to memory file
            import json

            from patchi.core.constants import MEMORY_FILES, MemoryCategory

            mem_path = self.root / MEMORY_FILES[MemoryCategory.PATCHES]
            mem_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = mem_path.with_suffix(".tmp")
            with tmp_path.open("w", encoding="utf-8") as f:
                json.dump(patches, f, indent=2)
            # Atomic replace
            import sys

            if sys.platform == "win32":
                # Windows doesn't support atomic rename over existing file
                if mem_path.exists():
                    mem_path.unlink()
            tmp_path.rename(mem_path)
        except Exception as e:
            _log.warning("Failed to persist patch state for %s (state=%s): %s", patch_id, state, e)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _ms(t0: float) -> int:
    return int((time.monotonic() - t0) * 1000)
