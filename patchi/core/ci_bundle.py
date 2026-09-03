"""
CI/PR Bundle — Finding stable id + Baseline+delta + --since + SARIF + fix --safe-all.

Stable id: hash(file+type+line//5) for dedup across runs.
Renderer registry: markdown/json/sarif renderers.
"""

from __future__ import annotations

import hashlib
import json
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
        out = subprocess.run(["git","diff","--name-only", since_ref], capture_output=True, text=True, timeout=5, cwd=str(root))
        if out.returncode != 0:
            return findings
        changed = set(out.stdout.splitlines())
        return [f for f in findings if f.get("file","") in changed]
    except Exception:
        return findings

def to_sarif(findings: list[dict], root: Path | None = None) -> dict:
    rules=[]
    results=[]
    seen=set()
    for f in findings:
        rule_id=f.get("type","")
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({"id": rule_id, "name": rule_id, "shortDescription": {"text": f.get("message","")[:100]}})
        results.append({
            "ruleId": rule_id,
            "level": "error" if f.get("severity") in ("high","critical") else "warning",
            "message": {"text": f.get("message","")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("file","")}, "region": {"startLine": f.get("line",1)}}}]
        })
    return {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Patchi","rules":rules}},"results":results}]}

def write_sarif(findings: list[dict], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_sarif(findings), indent=2), encoding="utf-8")
