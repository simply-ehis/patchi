"""
SecurityFixer - Patches confirmed vulnerabilities from security scanner agents.
"""

from __future__ import annotations

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    register,
)
from patchi.core.fix.patch import FileChange, Patch, PatchType

# Import common functionality from base module
from .base import _make_patch, _read_file, compute_blast_radius


@register
class SecurityFixer(BaseAgent):
    """Patches confirmed vulnerabilities from security scanner agents."""

    name = "SecurityFixer"
    group = AgentGroup.FIX
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        from patchi.core.ai.prompts import Skill
        from patchi.core.fix.fix_agents import _ai_fix

        findings = [
            f
            for f in inp.extra.get("findings", [])
            if (f.get("fix_agent") == self.name or f.get("severity") in ("critical", "high"))
            and f.get("type") not in ("hardcoded_secret",)
        ]

        patches: list[Patch] = []

        for finding in findings[:5]:
            fpath = finding.get("file", "")
            path = inp.root / fpath
            original = _read_file(path)
            if not original:
                continue

            framework = finding.get("framework", "")
            blast_radius = 0
            if hasattr(inp, "extra") and "brain_report" in inp.extra:
                brain_report = inp.extra["brain_report"]
                if hasattr(brain_report, "blast_radius_map") and fpath in brain_report.blast_radius_map:
                    blast_radius = len(brain_report.blast_radius_map[fpath].all_dependents)
            else:
                blast_radius = compute_blast_radius(fpath, inp.root)

            proposed = _ai_fix(
                inp.config,
                Skill.SECURITY_FIX,
                fpath,
                original,
                finding,
                blast_radius,
                root=inp.root,
                framework=framework,
            )
            if not proposed:
                continue

            change = FileChange(path=fpath, original=original, proposed=proposed)
            if not change.diff.strip():
                continue

            cwe = finding.get("cwe", "")
            issue_desc = finding.get("message", "Security vulnerability")
            patch = _make_patch(
                agent_name=self.name,
                patch_type=PatchType.SECURITY,
                changes=[change],
                description=f"Security fix: {issue_desc[:60]}",
                ai_explanation=f"CWE-{cwe}: {issue_desc}",
                finding_id=finding.get("type", ""),
                blast_radius=blast_radius,
            )
            patches.append(patch)
            result.data.setdefault("patches", []).append(patch.to_dict())

        result.files_scanned = len(findings)
        result.data["patch_count"] = len(patches)
        result.ai_calls_made = len(patches)
