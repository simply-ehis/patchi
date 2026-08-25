"""
Patch data model and risk scoring for Patchi.

A Patch is a proposed code change produced by a fix agent.
It is NOT applied automatically — it goes through the risk gate first.

Patch lifecycle:
  proposed → [risk gate] → pending | auto_applied | rejected
  pending  → accepted (user) → applying → applied | rolled_back
  applied  → undone → rolled_back

Risk score (0–100):
  0–30   LOW     safe to auto-apply in AUTO mode
  31–60  MEDIUM  logic changes — require review in CONFIRM mode
  61–100 HIGH    auth, payments, data — always ask regardless of mode

Risk factors (additive):
  +10  each file beyond the first (multi-file patch)
  +8   each function signature changed
  +5   per 20 lines changed (capped at +30)
  +25  touches auth/payment/session/token files or routes
  +20  touches database schema or migration
  +15  changes error handling (try/except/catch blocks modified)
  +10  blast radius > 5 (many files depend on changed file)
  +5   blast radius > 2

Confidence score (0–100):
  Starts at 100. Deductions:
  -20  fix agent had < 80% certainty about root cause
  -15  file parse had errors
  -10  test suite absent for this file
  -10  fix modifies a file with no test coverage
  -5   multiple possible interpretations of the issue
"""

from __future__ import annotations

import difflib
import re as _re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

# ── Helpers (must be defined before class field defaults reference them) ────────


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_diff(path: str, original: str, proposed: str) -> str:
    lines_a = original.splitlines(keepends=True)
    lines_b = proposed.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            lines_a,
            lines_b,
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
        )
    )


# ── Patch states ───────────────────────────────────────────────────────────────


class PatchState(str, Enum):
    PROPOSED = "proposed"  # created by fix agent, not yet gated
    PENDING = "pending"  # passed risk gate, waiting for user
    AUTO_APPLIED = "auto_applied"  # applied automatically (AUTO/AUTOPILOT mode, low risk)
    APPLYING = "applying"  # currently being written to disk
    APPLIED = "applied"  # written to disk, tests passed
    FAILED = "failed"  # applied but tests failed, rolled back
    ROLLED_BACK = "rolled_back"  # reverted via snapshot
    REJECTED = "rejected"  # user explicitly rejected
    UNDONE = "undone"  # user undone after apply


# ── Patch types ────────────────────────────────────────────────────────────────


class PatchType(str, Enum):
    BUG_FIX = "bug_fix"
    SECURITY = "security"
    DEAD_CODE = "dead_code"
    DEPENDENCY = "dependency"
    ENV_FIX = "env_fix"
    TYPE_FIX = "type_fix"
    REFACTOR = "refactor"
    TEST_ADD = "test_add"
    CONFIG = "config"
    PERF = "perf"


# ── File change ────────────────────────────────────────────────────────────────


@dataclass
class FileChange:
    """A single file's change within a patch."""

    path: str  # relative path
    original: str  # original content (before fix)
    proposed: str  # proposed content (after fix)
    diff: str = ""  # unified diff (computed on creation)

    def __post_init__(self) -> None:
        if not self.diff:
            self.diff = _compute_diff(self.path, self.original, self.proposed)

    @property
    def lines_added(self) -> int:
        return sum(
            1
            for line in self.diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )

    @property
    def lines_removed(self) -> int:
        return sum(
            1
            for line in self.diff.splitlines()
            if line.startswith("-") and not line.startswith("---")
        )

    @property
    def lines_changed(self) -> int:
        return self.lines_added + self.lines_removed

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "diff": self.diff,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            # original/proposed stored for review display — not for rollback (snapshot used)
            "original": self.original,
            "proposed": self.proposed,
        }


# ── Patch ──────────────────────────────────────────────────────────────────────


@dataclass
class Patch:
    """
    A proposed code change from a fix agent.
    Immutable after creation — never modify in place.
    """

    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent: str = ""  # fix agent that produced this
    patch_type: PatchType = PatchType.BUG_FIX
    finding_id: str = ""  # the finding this fixes (from scanner)

    # Content
    changes: list[FileChange] = field(default_factory=list)
    description: str = ""  # human-readable summary
    ai_explanation: str = ""  # why this fix is correct

    # Scoring
    risk_score: int = 0  # 0–100
    confidence: int = 100  # 0–100
    blast_radius: int = 0  # total files affected by changing target files

    # State
    state: PatchState = PatchState.PROPOSED
    snapshot_id: str = ""  # snapshot taken before applying

    # Timestamps
    proposed_at: str = field(default_factory=_now)
    applied_at: str = ""
    rejected_at: str = ""
    rolled_back_at: str = ""

    # Test results (populated after apply)
    test_result: dict = field(default_factory=dict)

    # Detect-fix-verify loop (MISS-15)
    scanner_agent: str = ""  # scanner agent that found the original issue
    source_finding: dict = field(default_factory=dict)  # original finding dict
    verify_retries: int = 0  # number of retries remaining (max 2)

    # Test-weakening guard: a fix that only edits test files must go to
    # human review, never auto-apply (set by the verify loop / risk gate).
    requires_review: bool = False

    # Metadata
    extra: dict = field(default_factory=dict)

    @property
    def file_count(self) -> int:
        return len(self.changes)

    @property
    def total_lines_changed(self) -> int:
        return sum(c.lines_changed for c in self.changes)

    @property
    def affected_paths(self) -> list[str]:
        return [c.path for c in self.changes]

    @property
    def risk_level(self) -> str:
        from patchi.core.constants import RiskLevel

        return RiskLevel.from_score(self.risk_score).value

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent": self.agent,
            "patch_type": self.patch_type.value,
            "finding_id": self.finding_id,
            "changes": [c.to_dict() for c in self.changes],
            "description": self.description,
            "ai_explanation": self.ai_explanation,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "blast_radius": self.blast_radius,
            "state": self.state.value,
            "snapshot_id": self.snapshot_id,
            "proposed_at": self.proposed_at,
            "applied_at": self.applied_at,
            "rejected_at": self.rejected_at,
            "rolled_back_at": self.rolled_back_at,
            "test_result": self.test_result,
            "scanner_agent": self.scanner_agent,
            "source_finding": self.source_finding,
            "verify_retries": self.verify_retries,
            "requires_review": self.requires_review,
            "file_count": self.file_count,
            "total_lines": self.total_lines_changed,
            "affected_paths": self.affected_paths,
        }

    @staticmethod
    def from_dict(d: dict) -> "Patch":
        changes = [
            FileChange(
                path=c["path"],
                original=c.get("original", ""),
                proposed=c.get("proposed", ""),
                diff=c.get("diff", ""),
            )
            for c in d.get("changes", [])
        ]
        p = Patch(
            id=d.get("id", str(uuid.uuid4())[:8]),
            agent=d.get("agent", ""),
            patch_type=PatchType(d.get("patch_type", "bug_fix")),
            finding_id=d.get("finding_id", ""),
            changes=changes,
            description=d.get("description", ""),
            ai_explanation=d.get("ai_explanation", ""),
            risk_score=d.get("risk_score", 0),
            confidence=d.get("confidence", 100),
            blast_radius=d.get("blast_radius", 0),
            state=PatchState(d.get("state", "proposed")),
            snapshot_id=d.get("snapshot_id", ""),
            proposed_at=d.get("proposed_at", _now()),
            applied_at=d.get("applied_at", ""),
            rejected_at=d.get("rejected_at", ""),
            rolled_back_at=d.get("rolled_back_at", ""),
            test_result=d.get("test_result", {}),
            scanner_agent=d.get("scanner_agent", ""),
            source_finding=d.get("source_finding", {}),
            verify_retries=d.get("verify_retries", 0),
            requires_review=d.get("requires_review", False),
        )
        return p


# ── Risk scorer ────────────────────────────────────────────────────────────────

# Patterns that indicate high-risk areas
_HIGH_RISK_PATHS = [
    "auth",
    "login",
    "oauth",
    "session",
    "token",
    "password",
    "payment",
    "stripe",
    "checkout",
    "billing",
    "invoice",
    "migration",
    "schema",
    "database",
    "db",
    "admin",
    "permission",
    "role",
    "secret",
    "credential",
]

_HIGH_RISK_PATTERN = _re.compile("|".join(_HIGH_RISK_PATHS), _re.IGNORECASE)


def compute_risk_score(
    changes: list[FileChange],
    blast_radius: int = 0,
    extra_signals: dict | None = None,
) -> int:
    """
    Compute risk score (0–100) for a set of file changes.
    Higher = more dangerous.
    """
    score = 0
    extra = extra_signals or {}

    # Multi-file penalty
    if len(changes) > 1:
        score += min((len(changes) - 1) * 10, 30)

    # Lines changed
    total_lines = sum(c.lines_changed for c in changes)
    score += min((total_lines // 20) * 5, 30)

    # High-risk path detection
    for change in changes:
        if _HIGH_RISK_PATTERN.search(change.path):
            score += 25
            break  # only penalise once even if multiple high-risk files

    # Database / schema changes
    if any("migration" in c.path.lower() or "schema" in c.path.lower() for c in changes):
        score += 20

    # Error handling changes
    import re

    error_pattern = re.compile(r"(try:|except|catch\s*\(|finally:|\.catch\()")
    for change in changes:
        diff_lines = change.diff.splitlines()
        modified = [
            line[1:]
            for line in diff_lines
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
        ]
        if any(error_pattern.search(line) for line in modified):
            score += 15
            break

    # Function signature changes
    sig_pattern = re.compile(r"^[+-]\s*(def |function |async def |async function )")
    for change in changes:
        sig_changes = [line for line in change.diff.splitlines() if sig_pattern.match(line)]
        score += min(len(sig_changes) * 8, 24)

    # Blast radius
    if blast_radius > 10:
        score += 10
    elif blast_radius > 2:
        score += 5

    # Agent-provided signals
    if extra.get("touches_contract"):
        score += 20
    if extra.get("no_test_coverage"):
        score += 10

    return min(100, max(0, score))


def compute_confidence(
    changes: list[FileChange],
    agent_certainty: float = 1.0,
    has_parse_errors: bool = False,
    has_test_coverage: bool = True,
    multiple_interpretations: bool = False,
) -> int:
    """
    Compute confidence score (0–100). Higher = more certain this fix is correct.
    """
    score = 100

    score -= int((1.0 - agent_certainty) * 20)

    if has_parse_errors:
        score -= 15

    if not has_test_coverage:
        score -= 20

    if multiple_interpretations:
        score -= 5

    return min(100, max(0, score))


# ── PatchApplier (for auto_fixer integration) ─────────────────────────────────

def list_patches(root: Path) -> list[dict]:
    """List all patches in .patchi/patches/."""
    patches_dir = root / ".patchi" / "patches"
    if not patches_dir.is_dir():
        return []
    results = []
    for p in patches_dir.glob("*.json"):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            results.append(data)
        except Exception:
            continue
    return results


def save_patch(root: Path, patch: Patch) -> Path:
    """Save a patch to .patchi/patches/."""
    patches_dir = root / ".patchi" / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    path = patches_dir / f"{patch.id}.json"
    path.write_text(json.dumps(patch.to_dict(), indent=2), encoding="utf-8")
    return path


def save_patch_state(root: Path, patch_id: str, state: PatchState) -> None:
    """Update the state of a saved patch."""
    path = root / ".patchi" / "patches" / f"{patch_id}.json"
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["state"] = state.value
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass


class PatchApplier:
    """Apply patches to the codebase."""

    def __init__(self, root: Path):
        self.root = root

    def apply(self, patch: Patch) -> dict:
        """Apply all changes in a patch. Returns a result dict."""
        applied = []
        errors = []
        for change in patch.changes:
            try:
                target = self.root / change.path
                if not target.parent.is_dir():
                    target.parent.mkdir(parents=True, exist_ok=True)
                if change.original and target.is_file():
                    content = target.read_text(encoding="utf-8", errors="ignore")
                    if change.original in content:
                        content = content.replace(change.original, change.proposed, 1)
                        target.write_text(content, encoding="utf-8")
                        applied.append(change.path)
                    else:
                        errors.append(f"Original text not found in {change.path}")
                else:
                    target.write_text(change.proposed, encoding="utf-8")
                    applied.append(change.path)
            except Exception as e:
                errors.append(f"{change.path}: {e}")

        # Save patch record
        save_patch(self.root, patch)
        if applied:
            save_patch_state(self.root, patch.id, PatchState.APPLIED)

        return {"applied": applied, "errors": errors, "patch_id": patch.id}
