"""Assurance route — assurance graph, campaigns, attackers, fuzz."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
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


@router.get("/api/assurance")
async def assurance_api(request: Request) -> JSONResponse:
    """JSON API for assurance data (for AJAX updates)."""
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


@router.get("/api/assurance/heatmap")
async def assurance_heatmap(request: Request) -> JSONResponse:
    """Return per-domain coverage data for the dashboard heatmap."""
    root = request.app.state.root
    from patchi.core.assurance.graph import AssuranceGraph

    graph = AssuranceGraph.load(root)
    coverage = graph.coverage()
    by_domain = coverage.get("by_domain", {})
    by_verdict = coverage.get("by_verdict", {})
    total = coverage.get("claims_total", 0)

    # Build heatmap tiles: one per domain with coverage %
    tiles = []
    for domain, counts in by_domain.items():
        proved = counts.get("proved", 0)
        domain_total = counts.get("total", 0)
        pct = round(proved / domain_total * 100) if domain_total > 0 else 0
        tiles.append({
            "domain": domain,
            "proved": proved,
            "total": domain_total,
            "coverage_pct": pct,
        })
    # Sort by coverage ascending (worst first)
    tiles.sort(key=lambda t: t["coverage_pct"])

    # Overall stats
    proved_total = by_verdict.get("proved", 0)
    disproved_total = by_verdict.get("disproved", 0)
    unproven_total = by_verdict.get("unproven", 0)
    not_proved_total = by_verdict.get("not_proved", 0)
    overall_pct = round(proved_total / total * 100) if total > 0 else 0

    return JSONResponse({
        "ok": True,
        "overall_pct": overall_pct,
        "total_claims": total,
        "proved": proved_total,
        "disproved": disproved_total,
        "unproven": unproven_total,
        "not_proved": not_proved_total,
        "tiles": tiles,
    })


@router.post("/api/assurance/run-dast")
async def run_dast_scan(request: Request):
    """Trigger a DAST scan and return results."""
    root = request.app.state.root
    try:
        # Discover running app URL
        import httpx

        from patchi.core import memory as mem
        from patchi.core.security.dast_agent import DASTAgent
        target_url = None
        for port in (8000, 3000, 5000, 8080, 1612):
            url = f"http://127.0.0.1:{port}"
            try:
                r = httpx.get(url, timeout=2.0)
                if r.status_code < 500:
                    target_url = url
                    break
            except Exception:
                continue

        if not target_url:
            return JSONResponse({
                "ok": False,
                "error": "No running app found. Start your app first (e.g. p web).",
            })

        # Run DAST agent
        agent = DASTAgent(root)
        result = agent.scan(target_url)

        # Save results to memory
        scan_results = mem.get_scan_results(root)
        scan_results["DASTAgent"] = {
            "tests_run": result.get("tests_run", 0),
            "target_url": target_url,
            "findings": result.get("findings", []),
        }
        mem.save_scan_results(scan_results, root)

        return JSONResponse({
            "ok": True,
            "target_url": target_url,
            "tests_run": result.get("tests_run", 0),
            "findings_count": len(result.get("findings", [])),
            "findings": result.get("findings", []),
        })
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


@router.get("/api/assurance/dast-screenshots")
async def list_dast_screenshots(request: Request):
    """List DAST screenshots for comparison view."""
    root = request.app.state.root
    evidence_dir = root / ".patchi" / "evidence" / "dast"
    visual_dir = root / ".patchi" / "visual_baselines"

    screenshots = []

    # Scan evidence/dast/ directory
    if evidence_dir.is_dir():
        for f in sorted(evidence_dir.rglob("*.png"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                screenshots.append({
                    "path": str(f.relative_to(root)),
                    "name": f.stem,
                    "timestamp": datetime.fromtimestamp(f.stat().st_mtime, UTC).isoformat(),
                    "size": f.stat().st_size,
                    "source": "dast",
                })
            except Exception:
                pass

    # Scan visual_baselines/current/ directory
    current_dir = visual_dir / "current"
    if current_dir.is_dir():
        for f in sorted(current_dir.rglob("*.png"), key=lambda x: x.stat().st_mtime, reverse=True):
            try:
                screenshots.append({
                    "path": str(f.relative_to(root)),
                    "name": f.stem,
                    "timestamp": datetime.fromtimestamp(f.stat().st_mtime, UTC).isoformat(),
                    "size": f.stat().st_size,
                    "source": "visual",
                })
            except Exception:
                pass

    # Scan visual_baselines/baselines/ directory (saved baselines)
    baselines_dir = visual_dir / "baselines"
    baselines = []
    if baselines_dir.is_dir():
        for f in sorted(baselines_dir.glob("*.png")):
            try:
                meta_file = f.with_suffix(".json")
                meta = {}
                if meta_file.exists():
                    import json
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                baselines.append({
                    "path": str(f.relative_to(root)),
                    "name": f.stem,
                    "timestamp": meta.get("created_at", datetime.fromtimestamp(f.stat().st_mtime, UTC).isoformat()),
                    "size": f.stat().st_size,
                })
            except Exception:
                pass

    return JSONResponse({
        "ok": True,
        "screenshots": screenshots[:50],  # Limit to 50 most recent
        "baselines": baselines[:20],  # Limit to 20 baselines
        "total": len(screenshots),
    })


@router.get("/api/assurance/screenshot/{path:path}")
async def serve_screenshot(path: str, request: Request):
    """Serve a screenshot file."""
    root = request.app.state.root
    file_path = root / path

    # Security: only allow serving from .patchi directory
    try:
        file_path.resolve().relative_to(root.resolve())
    except ValueError:
        return JSONResponse({"error": "Access denied"}, status_code=403)

    if not file_path.exists() or not file_path.is_file():
        return JSONResponse({"error": "File not found"}, status_code=404)

    from starlette.responses import FileResponse
    return FileResponse(file_path, media_type="image/png")


@router.post("/api/assurance/fix-headers")
async def fix_security_headers(request: Request):
    """Fix missing security headers based on DAST findings."""
    root = request.app.state.root
    try:
        body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    except Exception:
        body = {}

    dry_run = body.get("dry_run", False)

    # Get DAST findings from memory
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    dast_findings = []

    if "DASTAgent" in scan_results:
        for f in scan_results["DASTAgent"].get("findings", []):
            # Only include header-related findings
            ftype = f.get("type", "")
            if "header" in ftype or "csp" in ftype or "hsts" in ftype or "frame" in ftype:
                dast_findings.append(f)

    if not dast_findings:
        return JSONResponse({
            "ok": True,
            "message": "No header findings to fix",
            "fixed_count": 0,
        })

    # Apply fixes
    from patchi.core.security.auto_fixer import fix_missing_headers
    result = fix_missing_headers(root, dast_findings, apply=not dry_run)

    return JSONResponse({
        "ok": True,
        "dry_run": dry_run,
        "fixed_count": result.get("fixed_count", 0),
        "fixes": result.get("fixes", []),
        "skipped": result.get("skipped", []),
        "file": result.get("file"),
        "error": result.get("error"),
    })
