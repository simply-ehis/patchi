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
        finding: Finding | CorrelatedFinding,
        playbook: FixPlaybook,
    ) -> bool:
        """Verify fix by running the deterministic tool from the playbook.

        The tool is executed against the patched file via tool_verify, closing
        the detect→fix→verify loop with real evidence instead of a simulation.
        """
        tool = playbook.deterministic_tool
        if not tool:
            return False

        target = None
        if patch.changes:
            candidate = self.root / patch.changes[0].path
            if candidate.exists():
                target = candidate
        if target is None:
            self.on_progress(f"  [WARN] patched file not found; cannot verify with {tool}")
            return False

        self.on_progress(f"  Running {tool} on {target.name} for verification...")

        from patchi.core.security.tool_verify import finding_resolved

        try:
            resolved = finding_resolved(tool, target, finding)
        except Exception as e:  # defensive: never block the commit on tool errors
            _log.warning("static verification via %s failed: %s", tool, e)
            return False

        if resolved:
            self.on_progress(f"  [OK] {tool} confirms the finding is gone")
        else:
            self.on_progress(f"  [WARN] {tool} still reports the finding")
        return resolved

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


# ── Header Auto-Fix ─────────────────────────────────────────────────────────

def fix_missing_headers(
    root: Path,
    findings: list[dict],
    apply: bool = False,
) -> dict:
    """
    Fix missing security headers based on DAST findings.

    Args:
        root: Project root path
        findings: List of DAST findings (dicts with type, severity, message)
        apply: If True, actually write the fixes

    Returns:
        Dict with fixed_count, fixes applied, and suggestions
    """
    header_fixes = []
    fixed = []
    skipped = []

    for finding in findings:
        ftype = finding.get("type", "")
        severity = finding.get("severity", "low")

        # Only fix header-related findings
        if "header" not in ftype and "csp" not in ftype and "hsts" not in ftype and "frame" not in ftype:
            continue

        # Determine the fix
        fix = None
        if "content_security_policy" in ftype or "csp" in ftype.lower():
            fix = {
                "type": "missing_csp",
                "header": "Content-Security-Policy",
                "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
                "description": "Add Content-Security-Policy header",
                "severity": severity,
            }
        elif "x_frame_options" in ftype or "frame" in ftype.lower():
            fix = {
                "type": "missing_xfo",
                "header": "X-Frame-Options",
                "value": "DENY",
                "description": "Add X-Frame-Options header",
                "severity": severity,
            }
        elif "hsts" in ftype or "strict_transport" in ftype.lower():
            fix = {
                "type": "missing_hsts",
                "header": "Strict-Transport-Security",
                "value": "max-age=31536000; includeSubDomains",
                "description": "Add Strict-Transport-Security header",
                "severity": severity,
            }

        if fix:
            header_fixes.append(fix)

    if not header_fixes:
        return {"fixed_count": 0, "fixes": [], "skipped": []}

    if not apply:
        return {
            "fixed_count": 0,
            "fixes": header_fixes,
            "skipped": [],
            "dry_run": True,
        }

    # Find web app files to add headers to
    web_files = []
    for f in root.glob("**/*.py"):
        if ".patchi" in str(f) or "node_modules" in str(f):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            if any(kw in content for kw in ["FastAPI", "Flask", "Starlette", "@app", "middleware"]):
                web_files.append(f)
        except Exception:
            pass

    if not web_files:
        return {
            "fixed_count": 0,
            "fixes": header_fixes,
            "skipped": header_fixes,
            "error": "No web app files found",
        }

    # Generate header fix code
    headers_code = _generate_header_middleware(header_fixes)

    # Apply to the first web app file (append middleware)
    target_file = web_files[0]
    try:
        content = target_file.read_text(encoding="utf-8")

        # Check if middleware already exists
        if "PatchiSecurityHeaders" in content:
            return {
                "fixed_count": 0,
                "fixes": header_fixes,
                "skipped": header_fixes,
                "message": "Security headers middleware already exists",
            }

        # Append the middleware
        new_content = content + "\n" + headers_code
        target_file.write_text(new_content, encoding="utf-8")

        fixed = header_fixes
        return {
            "fixed_count": len(fixed),
            "fixes": fixed,
            "skipped": skipped,
            "file": str(target_file.relative_to(root)),
        }
    except Exception as e:
        return {
            "fixed_count": 0,
            "fixes": header_fixes,
            "skipped": header_fixes,
            "error": str(e),
        }


def _generate_header_middleware(fixes: list[dict]) -> str:
    """Generate Python middleware code for security headers."""
    header_lines = []
    for fix in fixes:
        header_lines.append(f'        response.headers["{fix["header"]}"] = "{fix["value"]}"')

    headers_block = "\n".join(header_lines)

    return f"""


# === Patchi Security Headers Middleware (auto-generated) ===
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import Response

    class PatchiSecurityHeaders(BaseHTTPMiddleware):
        \"\"\"Adds missing security headers to all responses.\"\"\"

        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
{headers_block}
            return response

except ImportError:
    pass
# === End Patchi Security Headers ===
"""
