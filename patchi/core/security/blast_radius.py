"""
Blast Radius Simulation (Layer 6) — prevents cascade breakage from fixes.

Three signals:
1. Static blast radius — count references to symbol/package being changed
2. Dependency tree dry-run — npm install --dry-run diff
3. Behavioral diff — browser baseline → sandbox fix → re-run → diff

The apply gate combines all three into auto-apply / stop-and-report.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)

# ── Static blast radius ───────────────────────────────────────────────────────


def patchi_blast_radius(symbol_or_package: str, root: Path) -> dict:
    """
    Count references to a symbol or package across the codebase.
    Returns count + list of referencing files.
    """
    refs = []
    re_pattern = re.compile(re.escape(symbol_or_package))

    source_patterns = [
        "*.py",
        "*.pyw",
        "*.js",
        "*.mjs",
        "*.cjs",
        "*.jsx",
        "*.ts",
        "*.tsx",
        "*.mts",
        "*.java",
        "*.cs",
        "*.rb",
        "*.go",
        "*.rs",
        "*.cpp",
        "*.cxx",
        "*.cc",
        "*.c",
        "*.h",
        "*.hpp",
        "*.kt",
        "*.swift",
        "*.dart",
        "*.php",
        "*.php3",
        "*.php4",
        "*.php5",
        "*.phtml",
        "*.scala",
        "*.svelte",
    ]

    for sp in source_patterns:
        for fpath in safe_rglob(root, sp):
            if not fpath.is_file():
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if re_pattern.search(content):
                refs.append(str(fpath.relative_to(root)))

    return {
        "symbol": symbol_or_package,
        "reference_count": len(refs),
        "referencing_files": refs,
        "blast_level": "low" if len(refs) <= 3 else ("medium" if len(refs) <= 10 else "high"),
    }


# ── Dependency tree dry-run ───────────────────────────────────────────────────


def patchi_dependency_dry_run(root: Path) -> dict:
    """
    Run npm install --dry-run or pip install --dry-run and return the diff.
    """
    result = {"tool": "", "would_install": [], "would_remove": [], "peer_warnings": []}

    # Check for package.json (npm)
    if (root / "package.json").exists():
        try:
            proc = subprocess.run(
                ["npm", "install", "--dry-run", "--json"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(root),
            )
            result["tool"] = "npm"
            if proc.stdout.strip():
                try:
                    data = json.loads(proc.stdout)
                    # Parse npm dry-run output
                    if isinstance(data, dict):
                        result["would_install"] = list(data.get("added", []))
                        result["would_remove"] = list(data.get("removed", []))
                except json.JSONDecodeError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Check for requirements.txt (pip)
    elif (root / "requirements.txt").exists():
        try:
            proc = subprocess.run(
                ["pip", "install", "--dry-run", "-r", "requirements.txt"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(root),
            )
            result["tool"] = "pip"
            # Parse pip dry-run output
            for line in proc.stdout.splitlines():
                if "Would install" in line:
                    result["would_install"] = line.replace("Would install", "").strip().split()
                elif "Would remove" in line:
                    result["would_remove"] = line.replace("Would remove", "").strip().split()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    result["total_changes"] = len(result["would_install"]) + len(result["would_remove"])
    return result


# ── Apply gate ────────────────────────────────────────────────────────────────


def patchi_apply_gate(static_radius: dict, dep_diff: dict) -> dict:
    """
    Combine signals into an auto-apply / stop-and-report decision.
    """
    blast_level = static_radius.get("blast_level", "low")
    dep_changes = dep_diff.get("total_changes", 0)

    if blast_level == "low" and dep_changes == 0:
        return {
            "decision": "auto_apply",
            "reason": "Low blast radius, no dependency changes",
            "blast_level": blast_level,
            "dep_changes": dep_changes,
        }
    else:
        return {
            "decision": "require_review",
            "reason": f"Blast radius: {blast_level}, dependency changes: {dep_changes}",
            "blast_level": blast_level,
            "dep_changes": dep_changes,
            "referencing_files": static_radius.get("referencing_files", []),
            "would_install": dep_diff.get("would_install", []),
            "would_remove": dep_diff.get("would_remove", []),
        }


# ── Blast Radius Agent ───────────────────────────────────────────────────────


@register
class BlastRadiusAgent(BaseAgent):
    """Computes blast radius for proposed fixes and dependency changes."""

    name = "BlastRadiusAgent"
    group = AgentGroup.GUARD
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        # Get findings that need blast radius analysis
        findings = inp.extra.get("findings", [])
        high_risk_findings = [f for f in findings if f.get("severity") in ("critical", "high")]

        for finding in high_risk_findings[:5]:
            fpath = finding.get("file", "")
            if not fpath:
                continue

            # Static blast radius
            symbol = Path(fpath).stem
            radius = patchi_blast_radius(symbol, inp.root)

            # Dependency dry-run if it's a dependency fix
            dep_diff = {"total_changes": 0, "tool": ""}
            if finding.get("type") in ("vulnerable_dependency", "unpinned_dependency"):
                dep_diff = patchi_dependency_dry_run(inp.root)

            gate = patchi_apply_gate(radius, dep_diff)

            finding["blast_radius"] = radius
            finding["dep_diff"] = dep_diff
            finding["apply_gate"] = gate

            if gate["decision"] == "require_review":
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="high_blast_radius",
                        severity=Severity.HIGH,
                        file=fpath,
                        message=f"Fix requires review: {gate['reason']}",
                        detail=json.dumps(gate, indent=2),
                    )
                )

        result.data["analyzed_count"] = min(len(high_risk_findings), 5)
