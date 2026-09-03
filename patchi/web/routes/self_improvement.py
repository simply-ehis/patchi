"""Self-Improvement dashboard — agent profiles, learning, threat model."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

_log = logging.getLogger("patchi.web.routes.self_improvement")


router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def _load_json(root: Path, rel: str) -> dict:
    p = root / rel
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception as _exc:
            _log.warning('_load_json failed: %s', _exc)
    return {}


@router.get("/self-improvement", response_class=HTMLResponse)
async def self_improvement(request: Request):
    root = request.app.state.root

    # Agent profiles
    try:
        from patchi.core.ai.agent_profiler import get_all_profiles, get_profile_summary

        profile_summary = get_profile_summary(root)
        all_profiles = get_all_profiles(root)
        profiles_data = {k: v.to_dict() for k, v in all_profiles.items()}
    except Exception:
        profile_summary = {"agents": 0, "total_runs": 0, "total_cost": 0}
        profiles_data = {}

    # Learning summary
    try:
        from patchi.core.security.attack_feedback import get_learning_summary

        learning = get_learning_summary(root)
    except Exception:
        learning = {"acceptances": {}, "rejections": {}, "agent_trust": {}, "skip_types": []}

    # Threat model
    threat_model = _load_json(root, ".patchi/threat_model.json")

    # Fuzz corpus stats
    try:
        from patchi.core.fuzz.corpus import FuzzCorpus

        corpus = FuzzCorpus(root)
        corpus_stats = corpus.stats()
    except Exception:
        corpus_stats = {"total": 0, "avg_score": 0, "strategies": {}}

    # Ignore learner stats
    try:
        from patchi.core.security.ignore_learner import IgnoreLearner

        learner = IgnoreLearner(root)
        learner.build()
        ignore_count = len(learner.entries)
    except Exception:
        ignore_count = 0

    return templates.TemplateResponse(
        request,
        "self_improvement.html",
        {
            "request": request,
            "profile_summary": profile_summary,
            "profiles": profiles_data,
            "learning": learning,
            "threat_model": threat_model,
            "corpus_stats": corpus_stats,
            "ignore_count": ignore_count,
        },
    )


@router.get("/api/self-improvement")
async def api_self_improvement(request: Request):
    root = request.app.state.root
    try:
        from patchi.core.ai.agent_profiler import get_all_profiles, get_profile_summary
        from patchi.core.security.attack_feedback import get_learning_summary

        profile_summary = get_profile_summary(root)
        all_profiles = get_all_profiles(root)
        learning = get_learning_summary(root)
        threat_model = _load_json(root, ".patchi/threat_model.json")
        return JSONResponse(
            {
                "profiles": profile_summary,
                "agent_details": {k: v.to_dict() for k, v in all_profiles.items()},
                "learning": learning,
                "threat_model": threat_model,
            }
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
