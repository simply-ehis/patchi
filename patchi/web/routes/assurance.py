"""Assurance route — assurance graph, campaigns, attackers, fuzz."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/assurance", response_class=HTMLResponse)
async def assurance(request: Request):
    root = request.app.state.root

    from patchi.core.assurance.graph import AssuranceGraph

    graph = AssuranceGraph.load(root)
    coverage = graph.coverage()

    # Run attackers
    attacker_results = []
    try:
        from patchi.core.attackers import AttackPlanner

        planner = AttackPlanner(graph)
        plan = planner.plan()
        attack_results = planner.run_all()
        confirmed = [r for r in attack_results if r.confirmed]
        attacker_results = [r.to_dict() for r in confirmed[:20]]
    except Exception:
        pass

    # Run campaigns
    campaign_results = []
    try:
        from patchi.core.campaigns import CampaignOrchestrator

        orch = CampaignOrchestrator(graph)
        result = orch.run_all()
        campaign_results = [c.to_dict() for c in result.campaigns]
    except Exception:
        pass

    # Fuzz stats
    fuzz_endpoints = len([c for c in graph.claims.values() if "endpoint" in c.domain])

    # Build claims data for the template
    claims_data = []
    for claim in graph.claims.values():
        claims_data.append({
            "id": claim.id,
            "statement": claim.statement,
            "domain": claim.domain,
            "verdict": claim.verdict.value,
            "severity": claim.severity_if_disproved,
            "evidence_count": len(claim.evidence),
        })

    # Sort by verdict (disproved first)
    verdict_order = {"disproved": 0, "not_proved": 1, "unproven": 2, "proved": 3}
    claims_data.sort(key=lambda c: verdict_order.get(c["verdict"], 4))

    return templates.TemplateResponse(
        request,
        "assurance.html",
        {
            "request": request,
            "coverage": coverage,
            "claims": claims_data,
            "total_claims": len(claims_data),
            "attacker_results": attacker_results,
            "attacker_count": len(attacker_results),
            "campaign_results": campaign_results,
            "campaign_count": len(campaign_results),
            "fuzz_endpoints": fuzz_endpoints,
        },
    )


@router.get("/api/assurance", response_class=HTMLResponse)
async def assurance_api(request: Request):
    """JSON API for assurance data (for AJAX updates)."""
    import json
    from fastapi.responses import JSONResponse

    root = request.app.state.root
    from patchi.core.assurance.graph import AssuranceGraph

    graph = AssuranceGraph.load(root)
    coverage = graph.coverage()

    # Run attackers
    attacker_count = 0
    confirmed_count = 0
    try:
        from patchi.core.attackers import AttackPlanner

        planner = AttackPlanner(graph)
        attack_results = planner.run_all()
        confirmed = [r for r in attack_results if r.confirmed]
        attacker_count = len(attack_results)
        confirmed_count = len(confirmed)
    except Exception:
        pass

    # Run campaigns
    campaign_data = []
    try:
        from patchi.core.campaigns import CampaignOrchestrator

        orch = CampaignOrchestrator(graph)
        result = orch.run_all()
        campaign_data = [c.to_dict() for c in result.campaigns]
    except Exception:
        pass

    return JSONResponse({
        "coverage": coverage,
        "attacker": {"total": attacker_count, "confirmed": confirmed_count},
        "campaigns": campaign_data,
        "fuzz_endpoints": len([c for c in graph.claims.values() if "endpoint" in c.domain]),
    })
