"""
CI/PR Bundle — Finding stable id + Baseline+delta + --since + SARIF + fix --safe-all.

Stable id: hash(file+type+line//5) for dedup across runs.
Renderer registry: markdown/json/sarif renderers via register_renderer().
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

def stable_id(finding: dict) -> str:
    raw = f"{finding.get('file','')}:{finding.get('type','')}:{finding.get('line',0)//5}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]

def baseline_delta(baseline: list[dict], current: list[dict]) -> dict:
    b_ids = {stable_id(f) for f in baseline}
    c_ids = {stable_id(f) for f in current}
    added = [f for f in current if stable_id(f) not in b_ids]
    fixed = [f for f in baseline if stable_id(f) not in c_ids]
    return {"added": added, "fixed": fixed, "added_count": len(added), "fixed_count": len(fixed)}

def filter_since(findings: list[dict], since_ref: str, root: Path) -> list[dict]:
    """Filter findings to files changed since git ref."""
    try:
        import subprocess
        out = subprocess.run(["git","diff","--name-only", since_ref], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, cwd=str(root))
        if out.returncode != 0:
            return findings
        changed = set(out.stdout.splitlines())
        return [f for f in findings if f.get("file","") in changed]
    except Exception:
        return findings

def to_sarif(findings: list[dict], root: Path | None = None) -> dict:
    """Single SARIF implementation — delegates to export.sarif.

    (root kept for compat; SARIF carries no repo-root field.)
    """
    from patchi.core.export.sarif import convert_findings

    return convert_findings(findings)

def write_sarif(findings: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")


def render_markdown(findings: list[dict]) -> str:
    lines = ["# Patchi Findings", ""]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    def _sort_key(d: dict) -> tuple:
        return (order.get(d.get("severity", "info"), 5), d.get("file", ""))
    for f in sorted(findings, key=_sort_key):
        lines.append(
            f"- `{f.get('file', '?')}:{f.get('line', 0)}` "
            f"[{f.get('severity', 'info')}] {f.get('type', '?')} — {f.get('message', '')}"
        )
    return "\n".join(lines) + "\n"


RENDERERS: dict[str, Callable[[list[dict]], str]] = {
    "markdown": render_markdown,
    "json": lambda findings: json.dumps(findings, indent=2),
    "sarif": lambda findings: json.dumps(to_sarif(findings), indent=2),
}


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def exit_code_for(findings: list[dict], fail_on: str | None) -> int:
    """CI gate: 1 when any finding meets the --fail-on severity, else 0.

    No threshold (None) never fails — plain `p scan` stays exit 0.
    """
    if not fail_on:
        return 0
    try:
        bar = _SEV_ORDER[fail_on.lower()]
    except KeyError:
        raise ValueError(f"unknown severity {fail_on!r} (have: {sorted(_SEV_ORDER)})") from None
    for f in findings:
        sev = f.get("severity", "info")
        sev = sev.value if hasattr(sev, "value") else str(sev)
        if _SEV_ORDER.get(sev.lower(), 5) <= bar:
            return 1
    return 0


def register_renderer(name: str, fn: Callable[[list[dict]], str]) -> None:
    """Add or override a findings renderer (e.g. plugins)."""
    RENDERERS[name.lower()] = fn


def render_findings(findings: list[dict], fmt: str = "markdown") -> str:
    try:
        renderer = RENDERERS[fmt.lower()]
    except KeyError:
        raise ValueError(f"unknown findings format {fmt!r} (have: {sorted(RENDERERS)})") from None
    return renderer(findings)
