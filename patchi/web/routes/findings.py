"""Findings route — findings list with filters + chain/intent tabs."""

from __future__ import annotations

import json as _json
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _load_chain_intent(root: Path) -> dict:
    """Load persisted chain/intent data from the last scan."""
    ci_path = root / ".patchi" / "chain_intent.json"
    if ci_path.is_file():
        try:
            return _json.loads(ci_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"chains": [], "intent_report": None}


@router.get("/findings", response_class=HTMLResponse)
async def findings(request: Request):
    root = request.app.state.root
    from patchi.core import memory as mem

    mem.get_brain(root)
    scan_results = mem.get_scan_results(root)

    # Flatten findings from all agents and attach remediation
    all_findings = []
    try:
        from patchi.core.security.remediation import get_remediation, get_remediation_confidence
        has_remediation = True
    except ImportError:
        has_remediation = False

    for agent_name, data in scan_results.items():
        for f in data.get("findings", []):
            f["agent"] = agent_name
            # Attach remediation suggestion for non-chain findings
            if has_remediation:
                ftype = f.get("type", "")
                rem = get_remediation(ftype)
                if rem:
                    f["remediation"] = {
                        "action": rem.action,
                        "code_pattern": rem.code_pattern,
                        "auto_fixable": rem.auto_fixable,
                        "playbook_id": rem.playbook_id,
                        "confidence": round(get_remediation_confidence(ftype, root), 2),
                    }
            all_findings.append(f)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    # Load chain/intent data with remediation suggestions
    ci = _load_chain_intent(root)
    chains = ci.get("chains", [])
    intent = ci.get("intent_report")

    # Attach remediation to each chain step
    try:
        from patchi.core.security.remediation import get_remediation_for_step
        for chain in chains:
            chain["remediations"] = [
                get_remediation_for_step(step) for step in chain.get("steps", [])
            ]
    except ImportError:
        pass

    # Build chain-membership map: (file, line, type) -> list of chain indices
    chain_members: dict[str, list[int]] = {}
    for ci, chain in enumerate(chains):
        for step in chain.get("steps", []):
            key = f"{step.get('file', '')}:{step.get('line', 0)}:{step.get('type', '')}"
            chain_members.setdefault(key, []).append(ci)

    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "request": request,
            "findings": all_findings,
            "total": len(all_findings),
            "chains": chains,
            "intent": intent,
            "chain_members": chain_members,
        },
    )


@router.get("/api/chains")
async def api_chains(request: Request):
    """JSON endpoint for chain/intent data."""
    root = request.app.state.root
    return JSONResponse(_load_chain_intent(root))
