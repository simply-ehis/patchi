"""
CodeFixer - Surgical line-level bug and error patches.
Handles: null/undefined errors, missing error handling, off-by-one, type mismatch.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    register,
)
from patchi.core.debug import debug_context_from_finding
from patchi.core.fix.patch import FileChange, Patch, PatchType

# Import common functionality from base module
from .base import _call_ai, _extract_code_block, _make_patch, _read_file, compute_blast_radius
from .fix_agents import _detect_language


@register
class CodeFixer(BaseAgent):
    """
    Surgical line-level bug and error patches.
    Handles: null/undefined errors, missing error handling, off-by-one, type mismatch.
    """

    name = "CodeFixer"
    group = AgentGroup.FIX
    timeout = 120

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        findings = self._get_findings(
            inp, ["parse_error", "unprotected_sensitive_route", "bug", "test_failure"]
        )
        patches: list[Patch] = []
        debug_cache: dict[tuple[str, str], dict | None] = {}

        for finding in findings[:10]:
            ftype = finding.get("type", "")
            finding_file = finding.get("file", "")

            cache_key = (str(inp.root), finding_file)
            if cache_key not in debug_cache:
                debug_cache[cache_key] = debug_context_from_finding(finding, inp.root)
            dbg = debug_cache[cache_key]

            target_file = finding_file
            if ftype == "test_failure" and dbg:
                frames = dbg.get("frames") or []
                ti = dbg.get("trigger_frame", 0)
                if 0 <= ti < len(frames):
                    cand = frames[ti].get("path", "")
                    if cand:
                        p = Path(cand)
                        if not p.is_absolute():
                            p = inp.root / p
                        p = p.resolve()
                        try:
                            p.relative_to(inp.root.resolve())
                            if p.is_file():
                                # Normalise to forward slashes so patch paths stay
                                # consistent across platforms (the rest of the
                                # pipeline stores relative paths with '/' separators).
                                target_file = p.relative_to(inp.root).as_posix()
                        except ValueError:
                            pass

            fpath = target_file
            path = inp.root / fpath
            original = _read_file(path)
            if not original:
                continue

            blast_radius = 0
            if hasattr(inp, "extra") and "brain_report" in inp.extra:
                brain_report = inp.extra["brain_report"]
                if (
                    hasattr(brain_report, "blast_radius_map")
                    and fpath in brain_report.blast_radius_map
                ):
                    blast_radius = len(
                        brain_report.blast_radius_map[fpath].all_dependents
                    )
            else:
                blast_radius = compute_blast_radius(fpath, inp.root)

            lang = _detect_language(fpath)
            debug_section = ""
            if dbg:
                debug_section = (
                    f"\n\nRUNTIME STATE AT FAILURE:\n{json.dumps(dbg, indent=2)}"
                )

            test_context = ""
            if ftype == "test_failure" and finding_file:
                test_path = inp.root / finding_file
                test_content = _read_file(test_path)
                if test_content:
                    test_context = (
                        f"\n\nFailing test file ({finding_file}):\n"
                        f"```\n{test_content[:2000]}\n```"
                    )

            prompt = textwrap.dedent(f"""
                Fix this issue in the file below. Return ONLY the corrected file content
                inside a code block. Do not explain. Do not add comments. Make the
                minimal change needed.

                Language: {lang}
                Issue: {finding.get("message", "")}
                File: {fpath}
                Line: {finding.get("line", 0)}
                Suggestion: {finding.get("suggestion", "")}
                {test_context}

                File content:
                ```
                {original[:3000]}
                ```
                {debug_section}

                Return the full corrected file inside triple backticks.
            """).strip()

            ai_response = _call_ai(prompt, inp.config)
            if not ai_response:
                continue

            proposed = _extract_code_block(ai_response)
            if proposed == original or not proposed.strip():
                continue

            change = FileChange(path=fpath, original=original, proposed=proposed)
            if not change.diff.strip():
                continue

            patch = _make_patch(
                agent_name=self.name,
                patch_type=PatchType.BUG_FIX,
                changes=[change],
                description=f"Fix: {finding.get('message', '')[:80]}",
                ai_explanation=finding.get("suggestion", ""),
                finding_id=finding.get("type", ""),
                blast_radius=blast_radius,
                # Only default the scanner to UnitTestAgent for test_failure
                # findings — for other types an empty scanner keeps the
                # applier's M-16 _verify_fix on its generic fallback path
                # instead of re-running the test suite inside apply().
                scanner_agent=(
                    "UnitTestAgent"
                    if ftype == "test_failure"
                    else finding.get("agent", "")
                ),
                source_finding=finding,
            )
            patches.append(patch)
            result.data.setdefault("patches", []).append(patch.to_dict())

        result.files_scanned = len(findings)
        result.data["patch_count"] = len(patches)
        result.ai_calls_made = len(patches)

    def _get_findings(self, inp: AgentInput, types: list[str]) -> list[Finding]:
        # Fix agents receive findings via extra dict (set by the fix command)
        all_findings = inp.extra.get("findings", [])
        return [
            f for f in all_findings if f.get("type") in types and f.get("fix_agent") == self.name
        ]
