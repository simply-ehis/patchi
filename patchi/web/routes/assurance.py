"""Assurance route — assurance graph, campaigns, attackers, fuzz."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from patchi.core.tenant import tenant_context

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/assurance", response_class=HTMLResponse)
async def assurance(request: Request):
    root = request.app.state.root
    tenant_ctx = tenant_context(root)
    tenant_ctx.__enter__()

    from patchi.core.assurance.graph import AssuranceGraph

    graph = AssuranceGraph.load(root)
    coverage = graph.coverage()

    # Run attackers
    attacker_results = []
    try:
        from patchi.core.attackers import AttackPlanner

        planner = AttackPlanner(graph)
        planner.plan()
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

    # DAST scan results (correlated with static analysis)
    dast_findings = []
    dast_tests_run = 0
    dast_target = ""
    try:
        from patchi.core import memory as mem
        mem.get_brain(root)
        scan_results = mem.get_scan_results(root)
        if "DASTAgent" in scan_results:
            dast_data = scan_results["DASTAgent"]
            dast_tests_run = dast_data.get("tests_run", 0)
            dast_target = dast_data.get("target_url", "")
            for f in dast_data.get("findings", []):
                dast_findings.append({
                    "type": f.get("type", "dast_unknown"),
                    "severity": f.get("severity", "low"),
                    "message": f.get("message", ""),
                    "file": f.get("file", dast_target),
                    "suggestion": f.get("suggestion", ""),
                    "code_snippet": (f.get("code_snippet", "") or "")[:500],
                    "source": "dast",
                })
        # Also load static analysis findings for cross-correlation
        static_high = []
        for agent_name, data in scan_results.items():
            if agent_name == "DASTAgent":
                continue
            for f in data.get("findings", []):
                if f.get("severity") in ("critical", "high"):
                    static_high.append({
                        "agent": agent_name,
                        "type": f.get("type", ""),
                        "severity": f.get("severity", ""),
                        "message": f.get("message", ""),
                        "file": f.get("file", ""),
                    })
    except Exception:
        pass

    # Correlate DAST findings with static analysis findings (same severity/type)
    dast_correlations = []
    for df in dast_findings:
        matches = [
            s for s in static_high
            if s["severity"] == df["severity"] or s["type"] in df["type"]
        ]
        if matches:
            dast_correlations.append({
                "dast": df,
                "static_matches": matches[:3],  # max 3 per DAST finding
            })
    dast_uncorrelated = [f for f in dast_findings if not any(
        c["dast"] == f for c in dast_correlations
    )]

    # Build claims data for the template
    claims_data = []
    for claim in graph.claims.values():
        claims_data.append(
            {
                "id": claim.id,
                "statement": claim.statement,
                "domain": claim.domain,
                "verdict": claim.verdict.value,
                "severity": claim.severity_if_disproved,
                "evidence_count": len(claim.evidence),
            }
        )

    # Sort by verdict (disproved first)
    verdict_order = {"disproved": 0, "not_proved": 1, "unproven": 2, "proved": 3}
    claims_data.sort(key=lambda c: verdict_order.get(c["verdict"], 4))

    # Chain/intent claims (from chain_to_assurance bridge)
    chain_claims = [c for c in claims_data if c["domain"] in ("exploit-chain", "intent-gap")]
    invariant_claims = [
        c for c in claims_data if c["domain"] not in ("exploit-chain", "intent-gap")
    ]

    # Load raw chain data for the chain explorer tab
    chain_raw = []
    try:
        ci_path = root / ".patchi" / "chain_intent.json"
        if ci_path.is_file():
            import json

            ci = json.loads(ci_path.read_text(encoding="utf-8"))
            chain_raw = ci.get("chains", [])
    except Exception:
        pass

    return templates.TemplateResponse(
        request,
        "assurance.html",
        {
            "request": request,
            "coverage": coverage,
            "claims": invariant_claims,
            "chain_claims": chain_claims,
            "total_claims": len(claims_data),
            "attacker_results": attacker_results,
            "attacker_count": len(attacker_results),
            "campaign_results": campaign_results,
            "campaign_count": len(campaign_results),
            "fuzz_endpoints": fuzz_endpoints,
            "chain_raw": chain_raw,
            "dast_findings": dast_findings,
            "dast_tests_run": dast_tests_run,
            "dast_target": dast_target,
            "dast_correlations": dast_correlations,
            "dast_uncorrelated": dast_uncorrelated,
        },
    )


@router.get("/api/assurance", response_class=HTMLResponse)
async def assurance_api(request: Request):
    """JSON API for assurance data (for AJAX updates)."""
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

    return JSONResponse(
        {
            "coverage": coverage,
            "attacker": {"total": attacker_count, "confirmed": confirmed_count},
            "campaigns": campaign_data,
            "fuzz_endpoints": len([c for c in graph.claims.values() if "endpoint" in c.domain]),
        }
    )
