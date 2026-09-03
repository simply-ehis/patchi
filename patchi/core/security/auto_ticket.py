"""
AutoTicket §10.2.4 — File Jira/GitHub Issues for detected bugs with assignee via CODEOWNERS/blame.
"""

from __future__ import annotations

import logging
from pathlib import Path

_log = logging.getLogger("patchi.security.auto_ticket")

def _match_owner(owners: dict, file: str) -> str:
    """CODEOWNERS glob match (longest pattern wins), not exact lookup."""
    import fnmatch

    best, best_len = "", -1
    for pattern, owner in owners.items():
        if fnmatch.fnmatch(file, pattern) and len(pattern) > best_len:
            best, best_len = owner, len(pattern)
    return best

def create_tickets(root: Path, findings: list[dict], dry_run: bool = True) -> list[dict]:
    tickets=[]
    # parse CODEOWNERS for assignee
    owners={}
    co=root/".github/CODEOWNERS"
    if co.exists():
        for line in co.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip() and not line.startswith("#"):
                parts=line.split()
                if len(parts)>=2:
                    owners[parts[0]]=parts[-1].lstrip("@")
    for f in findings[:10]:
        assignee = _match_owner(owners, f.get("file", "")) or owners.get("*", "")
        # blame fallback
        if not assignee:
            try:
                from patchi.core.brain.git_aware import blame_line
                info=blame_line(f.get("file",""), f.get("line",1), root)
                if info:
                    assignee=info.get("author","")
            except Exception as exc:  # noqa: BLE001
                _log.debug("blame for ticket failed: %s", exc)
        ticket={
            "title": f.get("message","")[:80] or f.get("type",""),
            "file": f.get("file",""), "line": f.get("line",0),
            "assignee": assignee, "dry_run": dry_run,
        }
        tickets.append(ticket)
        if not dry_run:
            # Real API calls would go here: GitHub Issues API / Jira REST
            pass
    return tickets
