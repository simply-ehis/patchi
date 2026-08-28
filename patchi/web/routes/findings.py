"""Findings route — findings list with filters + chain/intent tabs, DAST screenshots, history."""

from __future__ import annotations

import json as _json
import os
import sqlite3
from datetime import datetime
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


def _load_dast_evidence(root: Path) -> dict[str, dict]:
    """Load DAST screenshot evidence from .patchi/evidence/dast/."""
    evidence_dir = root / ".patchi" / "evidence" / "dast"
    evidence_map: dict[str, dict] = {}
    if not evidence_dir.is_dir():
        return evidence_map
    for entry in os.scandir(evidence_dir):
        if not entry.is_file():
            continue
        name = entry.name
        stem = Path(name).stem  # e.g. "dast_xss_reflected_abc123"
        # Strip the random suffix (last _XXXXX) to get the test name
        parts = stem.rsplit("_", 1)
        test_name = parts[0] if len(parts) > 1 else stem
        # Extract category from test name: "dast_xss_reflected" -> "xss"
        cat = ""
        if test_name.startswith("dast_"):
            cat = test_name[5:].split("_")[0]
        evidence_map.setdefault(cat, {}).setdefault(test_name, []).append(
            f"/evidence/dast/{name}"
        )
    return evidence_map


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

    # Collect DAST-specific metadata and scan stats
    dast_findings_count = 0
    dast_tests_run = 0
    dast_target = ""
    scan_agent_count = len(scan_results)

    for agent_name, data in scan_results.items():
        # Accumulate DAST metadata from the DASTAgent result
        if agent_name == "DASTAgent":
            dast_findings_count = data.get("findings_count", 0)
            dast_tests_run = data.get("tests_run", 0)
            dast_target = data.get("target_url", "")

        for f in data.get("findings", []):
            f["agent"] = agent_name
            # Flag DAST findings for template
            if agent_name == "DASTAgent" or f.get("type", "").startswith("dast_"):
                f["is_dast"] = True
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
    all_findings.sort(key=lambda f: (0 if f.get("is_dast") else 1, sev_order.get(f.get("severity", "info"), 5)))

    # Load DAST screenshot evidence
    dast_evidence = _load_dast_evidence(root)

    # Attach screenshot paths to DAST findings
    for f in all_findings:
        if f.get("is_dast"):
            ftype = f.get("type", "")
            cat = ftype.replace("dast_", "") if ftype.startswith("dast_") else ""
            if cat in dast_evidence:
                # Get first screenshot for this category
                screenshots = []
                for test_name, paths in dast_evidence[cat].items():
                    screenshots.extend(paths[:1])  # one per test type
                f["screenshots"] = screenshots[:3]  # max 3 per finding
            else:
                f["screenshots"] = []

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

    # Load charter violations
    charter_violations: list[dict] = []
    try:
        from patchi.core.security.charter import check_all_violations, load_charter
        charter = load_charter(root)
        if charter.rules:
            charter_violations = [v.to_dict() for v in check_all_violations(charter)]
    except Exception:
        pass

    # Load scan history
    scan_history = _load_scan_history(root)

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
            "charter_violations": charter_violations,
            "dast_findings_count": dast_findings_count,
            "dast_tests_run": dast_tests_run,
            "dast_target": dast_target,
            "scan_agent_count": scan_agent_count,
            "scan_history": scan_history,
        },
    )


@router.get("/api/chains")
async def api_chains(request: Request):
    """JSON endpoint for chain/intent data."""
    root = request.app.state.root
    return JSONResponse(_load_chain_intent(root))


@router.get("/api/findings/dast-evidence")
async def api_dast_evidence(request: Request):
    """JSON endpoint for DAST screenshot evidence."""
    root = request.app.state.root
    return JSONResponse(_load_dast_evidence(root))


def _load_scan_history(root: Path, limit: int = 50) -> list[dict]:
    """Load scan history from the SQLite database."""
    db_path = root / ".patchi" / "patchi_history.db"
    if not db_path.is_file():
        return []
    try:
        db = sqlite3.connect(str(db_path))
        cursor = db.cursor()
        cursor.execute(
            "SELECT scan_id, timestamp, tool, findings_count, "
            "severity_breakdown, duration_ms, health_score, metrics "
            "FROM scan_history ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = cursor.fetchall()
        db.close()
        results = []
        for row in rows:
            entry = {
                "scan_id": row[0],
                "timestamp": row[1],
                "tool": row[2],
                "findings_count": row[3],
                "severity_breakdown": _json.loads(row[4]) if row[4] else {},
                "duration_ms": row[5],
                "health_score": row[6],
                "metrics": _json.loads(row[7]) if row[7] else {},
            }
            results.append(entry)
        return results
    except Exception:
        return []


@router.get("/api/findings/history")
async def api_findings_history(request: Request, limit: int = 50):
    """JSON endpoint for scan history."""
    root = request.app.state.root
    return JSONResponse(_load_scan_history(root, limit))


@router.get("/api/findings/history/export")
async def api_findings_history_export(request: Request):
    """Export full scan history + current findings as JSON for CI/CD."""
    root = request.app.state.root
    history = _load_scan_history(root, limit=500)

    # Also include current findings snapshot
    from patchi.core import memory as mem
    scan_results = mem.get_scan_results(root)
    current_findings = []
    for agent_name, data in scan_results.items():
        for f in data.get("findings", []):
            f["agent"] = agent_name
            current_findings.append(f)

    export = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "project": str(root),
        "history": history,
        "current_findings": current_findings,
        "summary": {
            "total_scans": len(history),
            "total_findings": len(current_findings),
            "latest_health_score": history[0]["health_score"] if history else None,
        },
    }
    return JSONResponse(export)
