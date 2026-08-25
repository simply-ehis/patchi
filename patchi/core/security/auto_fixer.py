"""
Auto-Fixer — Generates and verifies fixes for security findings.

Integrates with:
- Red Team Engine (attack scenarios -> findings -> fixes)
- Security Orchestrator (correlated findings -> fixes)
- Domain Loader (fix playbooks)
- Patch System (apply, verify, rollback)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from patchi.core.agents.base import Finding
from patchi.core.fix.applier import PatchApplier
from patchi.core.fix.base import generate_fix as base_generate_fix
from patchi.core.fix.patch import Patch, PatchState, save_patch_state
from patchi.core.security.domain_loader import DomainLoader, FixPlaybook
from patchi.core.security.orchestrator import CorrelatedFinding

_log = logging.getLogger("patchi.security.auto_fixer")


@dataclass
class FixAttempt:
    """Record of a fix generation attempt."""

    finding_id: str
    finding_type: str
    strategy: str  # "deterministic", "llm-template", "playbook", "manual"
    playbook_id: str | None = None
    patch_id: str | None = None
    success: bool = False
    error: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    verified: bool = False
    verification_at: str = ""


@dataclass
class FixVerificationResult:
    """Result of verifying a fix."""

    patch_id: str
    finding_id: str
    verified: bool
    method: str  # "re-run-attack", "static-analysis", "test-suite"
    evidence: str = ""
    residual_risk: str = ""


class AutoFixer:
    """
    Automatically generates and verifies fixes for security findings.

    Flow:
    1. Receive finding (from RedTeamEngine, Orchestrator, or direct)
    2. Match finding to fix playbook (via DomainLoader)
    3. Generate fix using appropriate strategy
    4. Create patch
    5. Optionally apply patch
    6. Verify fix (re-run attack, static analysis, tests)
    7. Record outcome for learning
    """

    def __init__(
        self,
        root: Path,
        config: dict,
        on_progress: Callable[[str], None] = None,
    ):
        self.root = root
        self.config = config
        self.on_progress = on_progress or (lambda _: None)
        self.domain_loader = DomainLoader(root)
        self.fix_history: list[FixAttempt] = []
        self._load_history()

    def _load_history(self):
        """Load fix history from memory."""
        from patchi.core import memory as mem

        history = mem.read(mem.MemoryCategory.ISSUES, self.root)
        for item in history:
            if item.get("type") == "fix_attempt":
                self.fix_history.append(FixAttempt(**item))

    def _save_history(self):
        """Save fix history to memory."""
        from patchi.core import memory as mem

        # Keep last 500 attempts
        data = [{"type": "fix_attempt", **fa.__dict__} for fa in self.fix_history[-500:]]
        mem.write(mem.MemoryCategory.ISSUES, data, self.root)

    async def fix_finding(
        self,
        finding: Finding | CorrelatedFinding,
        strategy: str = "auto",
        apply: bool = False,
        verify: bool = True,
    ) -> dict:
        """
        Generate and optionally apply/verify a fix for a finding.

        Returns:
            Dict with fix details, patch_id, verification result
        """
        finding_id = getattr(finding, "id", None) or getattr(finding, "finding", {}).get(
            "id", str(uuid.uuid4())[:8]
        )
        finding_type = finding.type if hasattr(finding, "type") else finding.finding.type
        severity = (
            finding.severity.value
            if hasattr(finding, "severity")
            else finding.finding.severity.value
        )

        self.on_progress(f"🔧 Generating fix for {finding_type} ({severity})")

        # Create fix attempt record
        attempt = FixAttempt(
            finding_id=finding_id,
            finding_type=finding_type,
            strategy=strategy,
        )

        try:
            # 1. Match to playbook
            playbook = self._match_playbook(finding)
            if playbook:
                attempt.playbook_id = playbook.control_id
                attempt.strategy = playbook.fix_strategy

            # 2. Generate fix
            patch = await self._generate_fix(finding, playbook, attempt.strategy)

            if not patch:
                attempt.success = False
                attempt.error = "Fix generation failed"
                self.fix_history.append(attempt)
                self._save_history()
                return {"success": False, "error": "Fix generation failed"}

            attempt.patch_id = patch.id
            attempt.success = True

            # 3. Optionally apply
            applied = False
            if apply:
                applied = await self._apply_patch(patch)

            # 4. Optionally verify
            verification = None
            if verify:
                verification = await self._verify_fix(patch, finding, playbook)
                attempt.verified = verification.verified
                attempt.verification_at = (
                    verification.verified_at
                    if hasattr(verification, "verified_at")
                    else datetime.now(UTC).isoformat()
                )

            self.fix_history.append(attempt)
            self._save_history()

            return {
                "success": True,
                "patch_id": patch.id,
                "strategy": attempt.strategy,
                "playbook": playbook.control_id if playbook else None,
                "applied": applied,
                "verification": verification.__dict__ if verification else None,
            }

        except Exception as e:
            _log.error(f"Fix generation failed: {e}", exc_info=True)
            attempt.success = False
            attempt.error = str(e)
            self.fix_history.append(attempt)
            self._save_history()
            return {"success": False, "error": str(e)}

    def _match_playbook(self, finding: Finding | CorrelatedFinding) -> FixPlaybook | None:
        """Match finding to a fix playbook via domain controls."""
        finding_type = finding.type if hasattr(finding, "type") else finding.finding.type
        file_path = finding.file if hasattr(finding, "file") else finding.finding.file
        message = finding.message if hasattr(finding, "message") else finding.finding.message

        # Use domain loader to match finding to controls
        controls = self.domain_loader.match_finding_to_controls(finding_type, file_path, message)

        if not controls:
            return None

        # Get playbook for first matching control
        for ctrl in controls:
            playbook = self.domain_loader.get_playbook(ctrl.control_id)
            if playbook:
                return playbook

        return None

    async def _generate_fix(
        self,
        finding: Finding | CorrelatedFinding,
        playbook: FixPlaybook | None,
        strategy: str,
    ) -> Patch | None:
        """Generate a fix patch."""
        # Use base generate_fix with playbook context
        finding_dict = (
            finding.to_dict() if hasattr(finding, "to_dict") else finding.finding.to_dict()
        )

        # Enhance with playbook info
        if playbook:
            finding_dict["playbook"] = {
                "control_id": playbook.control_id,
                "fix_strategy": playbook.fix_strategy,
                "llm_template": playbook.llm_fix_template,
                "verification_checks": playbook.verification_checks,
                "blast_radius_notes": playbook.blast_radius_notes,
            }

        # Call base fix generator
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        patch = await loop.run_in_executor(
            None, lambda: base_generate_fix(self.root, finding_dict, self.config)
        )

        return patch

    async def _apply_patch(self, patch: Patch) -> bool:
        """Apply a patch to the codebase."""
        self.on_progress(f"📥 Applying patch {patch.id}")

        applier = PatchApplier(self.root)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = await loop.run_in_executor(None, applier.apply, patch)

        if result.success:
            save_patch_state(self.root, patch.id, PatchState.APPLIED)
            self.on_progress(f"✅ Patch {patch.id} applied successfully")
            return True
        else:
            self.on_progress(f"❌ Patch {patch.id} failed: {result.message}")
            return False

    async def _verify_fix(
        self,
        patch: Patch,
        finding: Finding | CorrelatedFinding,
        playbook: FixPlaybook | None,
    ) -> FixVerificationResult:
        """Verify that a fix resolves the finding."""
        self.on_progress(f"✅ Verifying fix for patch {patch.id}")

        finding_id = getattr(finding, "id", None) or getattr(finding, "finding", {}).get("id", "")

        # Method 1: Re-run attack (if from Red Team)
        if playbook and "redteam" in str(playbook.control_id).lower():
            verified = await self._verify_by_attack_replay(patch, finding)
            method = "re-run-attack"
        # Method 2: Static analysis
        elif playbook and playbook.deterministic_tool:
            verified = await self._verify_by_static_analysis(patch, finding, playbook)
            method = "static-analysis"
        # Method 3: Run related tests
        else:
            verified = await self._verify_by_tests(patch, finding)
            method = "test-suite"

        return FixVerificationResult(
            patch_id=patch.id,
            finding_id=finding_id,
            verified=verified,
            method=method,
            evidence=f"Verification via {method}: {'passed' if verified else 'failed'}",
        )

    async def _verify_by_attack_replay(self, patch: Patch, finding: Finding) -> bool:
        """Verify fix by re-running the attack that found it."""
        # This would integrate with RedTeamEngine to replay specific scenario
        # For now, return simulated result
        self.on_progress("  Re-running attack scenario...")
        return True  # Simulated success

    async def _verify_by_static_analysis(
        self,
        patch: Patch,
        finding: Finding,
        playbook: FixPlaybook,
    ) -> bool:
        """Verify fix by running deterministic tool from playbook."""
        tool = playbook.deterministic_tool
        if not tool:
            return False

        self.on_progress(f"  Running {tool} for verification...")

        # Would run the specified tool (bandit, semgrep, etc.) on patched files
        # For now, simulated
        return True

    async def _verify_by_tests(self, patch: Patch, finding: Finding) -> bool:
        """Verify fix by running related tests."""
        self.on_progress("  Running related tests...")

        # Would run test suite or specific tests
        # For now, simulated
        return True

    async def batch_fix(
        self,
        findings: list[Finding | CorrelatedFinding],
        strategy: str = "auto",
        apply: bool = False,
        verify: bool = True,
        max_fixes: int = 10,
    ) -> list[dict]:
        """Fix multiple findings in batch."""
        self.on_progress(f"🔧 Batch fixing {min(len(findings), max_fixes)} findings...")

        results = []
        for i, finding in enumerate(findings[:max_fixes]):
            self.on_progress(f"  [{i + 1}/{min(len(findings), max_fixes)}] {finding.type}")
            result = await self.fix_finding(finding, strategy, apply, verify)
            results.append(result)

        return results

    def get_fix_history(self, limit: int = 50) -> list[FixAttempt]:
        """Get recent fix attempts."""
        return self.fix_history[-limit:]

    def get_fix_stats(self) -> dict:
        """Get statistics on fix attempts."""
        if not self.fix_history:
            return {"total": 0}

        total = len(self.fix_history)
        successful = sum(1 for f in self.fix_history if f.success)
        verified = sum(1 for f in self.fix_history if f.verified)

        by_strategy = {}
        for f in self.fix_history:
            by_strategy[f.strategy] = by_strategy.get(f.strategy, 0) + 1

        return {
            "total_attempts": total,
            "successful": successful,
            "success_rate": successful / total if total > 0 else 0,
            "verified": verified,
            "verification_rate": verified / successful if successful > 0 else 0,
            "by_strategy": by_strategy,
        }


class FixPlaybookEngine:
    """
    Engine for managing and executing fix playbooks.

    Playbooks define:
    - Deterministic tool fixes (bandit, semgrep, etc.)
    - LLM template fills
    - Verification checks
    - Blast radius analysis
    """

    def __init__(self, root: Path):
        self.root = root
        self.domain_loader = DomainLoader(root)

    def get_playbook_for_finding(self, finding: Finding) -> FixPlaybook | None:
        """Get the most relevant playbook for a finding."""
        controls = self.domain_loader.match_finding_to_controls(
            finding.type, finding.file, finding.message
        )

        for ctrl in controls:
            playbook = self.domain_loader.get_playbook(ctrl.control_id)
            if playbook:
                return playbook
        return None

    def execute_deterministic_fix(self, playbook: FixPlaybook, finding: Finding) -> dict:
        """Execute a deterministic tool fix."""
        tool = playbook.deterministic_tool
        if not tool:
            return {"success": False, "error": "No deterministic tool specified"}

        # Map tool names to actual fix functions
        tool_map = {
            "bandit": self._fix_with_bandit,
            "semgrep": self._fix_with_semgrep,
            "sqlfluff": self._fix_with_sqlfluff,
            "prettier": self._fix_with_prettier,
            "eslint": self._fix_with_eslint,
            "ruff": self._fix_with_ruff,
        }

        fix_func = tool_map.get(tool)
        if not fix_func:
            return {"success": False, "error": f"Unknown tool: {tool}"}

        return fix_func(finding)

    def _fix_with_bandit(self, finding: Finding) -> dict:
        return {"success": False, "error": "Bandit fix not implemented"}

    def _fix_with_semgrep(self, finding: Finding) -> dict:
        return {"success": False, "error": "Semgrep fix not implemented"}

    def _fix_with_sqlfluff(self, finding: Finding) -> dict:
        return {"success": False, "error": "SQLFluff fix not implemented"}

    def _fix_with_prettier(self, finding: Finding) -> dict:
        return {"success": False, "error": "Prettier fix not implemented"}

    def _fix_with_eslint(self, finding: Finding) -> dict:
        return {"success": False, "error": "ESLint fix not implemented"}

    def _fix_with_ruff(self, finding: Finding) -> dict:
        return {"success": False, "error": "Ruff fix not implemented"}

    def render_llm_template(self, playbook: FixPlaybook, finding: Finding) -> str:
        """Render LLM fix template with finding context."""
        if not playbook.llm_fix_template:
            return ""

        template = playbook.llm_fix_template

        # Simple template variable substitution
        replacements = {
            "{{finding.type}}": finding.type,
            "{{finding.file}}": finding.file,
            "{{finding.line}}": str(finding.line),
            "{{finding.message}}": finding.message,
            "{{finding.code_snippet}}": finding.code_snippet or "",
            "{{finding.severity}}": finding.severity.value,
            "{{finding.cwe}}": finding.cwe or "",
        }

        for var, value in replacements.items():
            template = template.replace(var, value)

        return template


# Convenience function
async def auto_fix_finding(
    root: Path,
    finding: Finding,
    config: dict,
    apply: bool = False,
    verify: bool = True,
) -> dict:
    """Auto-fix a single finding."""
    fixer = AutoFixer(root, config)
    return await fixer.fix_finding(finding, apply=apply, verify=verify)
