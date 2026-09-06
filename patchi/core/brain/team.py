"""
Team Collaboration §10.3.1-4 — CODEOWNERS routing, knowledge base, gamification.
"""

from __future__ import annotations

from pathlib import Path

def route_to_team(root: Path, finding: dict) -> str:
    co=root/".github/CODEOWNERS"
    if co.exists():
        for line in co.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("#") or not line.strip(): continue
            parts=line.split()
            if len(parts)>=2 and finding.get("file","").startswith(parts[0].lstrip("/")):
                return parts[-1]
    return "unassigned"

def leaderboard(root: Path) -> list[dict]:
    try:
        # count fixes per author via git log
        import subprocess
        out=subprocess.run(["git","log","--pretty=format:%an","--since=1.month.ago"], capture_output=True, text=True, timeout=5, cwd=str(root))
        from collections import Counter
        cnt=Counter(out.stdout.splitlines()) if out.returncode==0 else Counter()
        return [{"author": a, "fixes": c} for a,c in cnt.most_common(5)]
    except Exception:
        return []
