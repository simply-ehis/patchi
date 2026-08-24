"""
Evidence Capture — screenshot/video evidence for security findings.

Captures browser screenshots and session recordings during security testing.
Stores evidence paths in findings for audit trail.

Requires: Playwright
"""

from __future__ import annotations
import logging

from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
)


_log = logging.getLogger("patchi.security.evidence")


def patchi_capture_screenshot(
    page, finding_id: str, evidence_dir: Path, step: int = 0
) -> str | None:
    """Capture a screenshot during a browser test. Returns file path."""
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{finding_id}_step_{step}.png"
        path = evidence_dir / filename
        page.screenshot(path=str(path), full_page=True)
        return str(path)
    except Exception as e:
        _log.warning("patchi_capture_screenshot failed: %s", e)
        return None


def patchi_start_recording(context, scan_id: str, evidence_dir: Path) -> str | None:
    """Start video recording for a browser context. Returns recording path on close."""
    try:
        record_dir = evidence_dir / scan_id
        record_dir.mkdir(parents=True, exist_ok=True)
        # Playwright handles recording via context manager
        return str(record_dir)
    except Exception as e:
        _log.warning("patchi_start_recording failed: %s", e)
        return None


def patchi_get_evidence_dir(root: Path) -> Path:
    """Get the standard evidence directory path."""
    return root / ".patchi" / "evidence"


# ── Evidence Agent ────────────────────────────────────────────────────────────


@register
class EvidenceAgent(BaseAgent):
    """Captures screenshots and video evidence for security findings."""

    name = "EvidenceAgent"
    group = AgentGroup.SECURITY
    timeout = 30

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        evidence_dir = patchi_get_evidence_dir(inp.root)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Check if Playwright is available
        try:
            import importlib.util

            has_playwright = importlib.util.find_spec("playwright") is not None
            result.data["playwright_available"] = has_playwright
        except (ImportError, ValueError):
            result.data["playwright_available"] = False
            result.add_finding(
                Finding(
                    agent=self.name,
                    type="playwright_missing",
                    severity=Severity.INFO,
                    file="",
                    message="Playwright not installed — evidence capture unavailable. pip install playwright",
                )
            )
            return

        # Record evidence directory location
        result.data["evidence_dir"] = str(evidence_dir)
        result.data["message"] = f"Evidence directory ready at {evidence_dir}"

        # Scan for existing evidence
        existing = list(evidence_dir.rglob("*.png")) + list(evidence_dir.rglob("*.webm"))
        result.data["existing_evidence_count"] = len(existing)
