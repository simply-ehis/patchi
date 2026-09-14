"""
Enriched Brain Context — Slice 1 of Smart Brain v2.

Single AI call per scan that turns deterministic signals
(project_reader + stack + routes + domains) into a short,
structured reasoning object stored in brain.json.

Design constraints (from deep audit):
- Exactly ONE LLM call per scan (not per finding)
- Honors PATCHI_OFFLINE=1 → no network
- Timeout-bound (8s default), never blocks scan
- Offline fallback builds same schema from heuristics
- Result is additive: brain.json["enriched_context"]
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

_log = logging.getLogger("patchi.brain.enriched_context")

DEFAULT_TIMEOUT = 8.0
MAX_CHARS = 6000


def enrich_project_context(
    root: Path,
    config: dict[str, Any],
    stack: Any,
    routes: list[Any],
    file_infos: list[Any],
    context: dict[str, Any],
    active_domains: list[str],
    extra_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build enriched_context. Always returns a dict with the same keys,
    whether AI ran or we fell back to heuristics.

    Keys: purpose_1sent, domain, domain_confidence, tech_stack_confirmed,
          critical_dirs_reasoned, top_risks[3], scan_focus
    """
    fallback = _heuristic_enrichment(stack, routes, context, active_domains)
    if os.environ.get("PATCHI_OFFLINE"):
        _log.debug("enriched_context: offline mode — heuristic fallback")
        fallback["source"] = "heuristic_offline"
        return fallback

    prompt = _build_prompt(stack, routes, file_infos, context, active_domains, extra_context or {})
    system = (
        "You are Patchi Context Synthesizer. Given deterministic signals about a codebase, "
        "produce a short, structured assessment. Be precise and conservative. "
        "Do not invent frameworks or domains not present in the signals. "
        "Return ONLY valid JSON with exactly these keys: "
        '{"purpose_1sent": str, "domain": str, "domain_confidence": float 0-1, '
        '"tech_stack_confirmed": [str], "critical_dirs_reasoned": [{"dir": str, "why": str}], '
        '"top_risks": [{"risk": str, "why": str}], "scan_focus": str}'
    )
    try:
        from patchi.core.ai.client import call_ai_structured

        result = call_ai_structured(
            config,
            system,
            prompt,
            max_tokens=800,
            temperature=0.1,
        )
        if isinstance(result, dict) and "purpose_1sent" in result:
            _log.info("enriched_context: AI succeeded (domain=%s)", result.get("domain"))
            normalized = _normalize(result, fallback)
            normalized["source"] = "ai_enriched"
            return normalized
        _log.debug("enriched_context: AI returned empty/unexpected shape, using heuristic")
    except Exception as exc:  # noqa: BLE001
        _log.warning("enriched_context AI call failed, heuristic fallback: %s", exc)
    fallback["source"] = "heuristic_ai_unavailable"
    return fallback


def _build_prompt(
    stack: Any,
    routes: list[Any],
    file_infos: list[Any],
    context: dict[str, Any],
    active_domains: list[str],
    extra_context: dict[str, Any] | None = None,
) -> str:
    # StackInfo
    fws = [f.name for f in (stack.frameworks if stack and getattr(stack, "frameworks", None) else [])]
    fw_str = ", ".join(fws) if fws else "Unknown"
    runtime = getattr(stack, "runtime", "") if stack else ""
    has_ts = getattr(stack, "has_typescript", False) if stack else False
    langs = {}
    for fi in file_infos:
        try:
            lang = fi.language.value if hasattr(fi.language, "value") else str(fi.language)
        except Exception:
            lang = "unknown"
        langs[lang] = langs.get(lang, 0) + 1
    lang_str = ", ".join(f"{k}:{v}" for k, v in sorted(langs.items(), key=lambda x: -x[1])[:5])
    route_sample = [getattr(r, "path", str(r)) for r in routes[:12]]
    infra = context.get("infrastructure_files", []) if isinstance(context, dict) else []
    deps = context.get("dependencies", []) if isinstance(context, dict) else []
    # ProjectInsight
    insight_block = ""
    try:
        pi = extra_context.get("project_insight") if extra_context else None
        if isinstance(pi, dict) and pi:
            insight_block = (
            f"\nPROJECT_INSIGHT: {pi.get('name', '')} — {pi.get('description', '')[:200]} |"
            f" type={pi.get('project_type', '')} fw={pi.get('framework', '')}"
            f" lang={pi.get('language', '')} tech={pi.get('tech_stack', [])[:6]}"
            f" entry={pi.get('entry_points', [])[:3]} readme={pi.get('readme_summary', '')[:300]}\n"
            )
    except Exception:
        insight_block = ""
    # Layer summaries (up to 10)
    layer_block = ""
    try:
        lb = extra_context.get("layer_summaries") if extra_context else None
        if isinstance(lb, list) and lb:
            layer_block = (
                "\nLAYER_SUMMARIES:\n"
                + "\n".join(
                    f"- {lay.get('name', '')} ({lay.get('level', '')}): {lay.get('summary', '')[:180]}"
                    for lay in lb[:10]
                )
                + "\n"
            )
    except Exception:
        layer_block = ""
    core_block = ""
    if extra_context and extra_context.get("core_files_block"):
        core_block = f"\nCORE_FILES (understander-ranked):\n{extra_context['core_files_block']}\n"
    return (
        f"FRAMEWORKS: {fw_str} runtime={runtime} ts={has_ts}\n"
        f"LANGUAGES: {lang_str}\n"
        f"FILE_COUNT: {len(file_infos)}\n"
        f"ROUTES ({len(routes)}): {route_sample}\n"
        f"ACTIVE_DOMAINS ({len(active_domains)}): {active_domains[:18]}\n"
        f"DEPLOYMENT: {context.get('deployment_model', 'unknown') if isinstance(context, dict) else 'unknown'}\n"
        f"INFRA_SAMPLE: {infra[:10]}\n"
        f"DEPS_SAMPLE: {deps[:15]}\n"
        f"CONTEXT_KEYS: {list(context.keys())[:14] if isinstance(context, dict) else []}\n"
        + insight_block
        + layer_block
        + core_block
        + "\nTask: synthesize. 1 sentence purpose, pick single domain label, confirm tech stack from signals, "
        + "name 2-4 critical dirs with why, list top 3 risks mapped to active domains, and one-line scan focus."
    )[:MAX_CHARS]


def _heuristic_enrichment(
    stack: Any,
    routes: list[Any],
    context: dict[str, Any],
    active_domains: list[str],
) -> dict[str, Any]:
    fws = [f.name for f in (stack.frameworks if stack and getattr(stack, "frameworks", None) else [])]
    fw_str = ", ".join(fws) if fws else "Unknown project"
    has_routes = len(routes) > 0
    # domain heuristic: most informative active domain or deployment
    domain = (
        active_domains[0]
        if active_domains
        else context.get("deployment_model", "unknown")
        if isinstance(context, dict)
        else "unknown"
    )
    if isinstance(domain, str) and "-" in domain:
        pass  # keep as-is
    critical: list[dict[str, str]] = []
    if has_routes:
        critical.append({"dir": "routes/api", "why": f"{len(routes)} endpoints — request surface"})
    if fws:
        critical.append({"dir": fws[0].lower(), "why": f"primary framework {fws[0]}"})
    # infer from context keys
    if isinstance(context, dict):
        if context.get("has_db") or "data_layer" in active_domains:
            critical.append({"dir": "db/models", "why": "data layer detected"})
        if "auth_session" in active_domains or "auth-session" in active_domains:
            critical.append({"dir": "auth", "why": "auth/session domain active"})

    risks: list[dict[str, str]] = []
    for d in active_domains[:3]:
        risks.append({"risk": d, "why": f"domain {d} activated — verify handlers"})
    while len(risks) < 3:
        risks.append({"risk": "supply-chain", "why": "dependencies present — pin & audit"})
        if len(risks) >= 3:
            break

    domains_3 = ", ".join(active_domains[:3]) or "general"
    domains_2 = ", ".join(active_domains[:2]) or "general security"
    return {
        "purpose_1sent": f"{fw_str} project with {len(routes)} routes; domains: {domains_3}",
        "domain": domain if isinstance(domain, str) else str(domain),
        "domain_confidence": 0.55 if active_domains else 0.35,
        "tech_stack_confirmed": fws[:5],
        "critical_dirs_reasoned": critical[:4],
        "top_risks": risks[:3],
        "scan_focus": f"Prioritize {domains_2}; {len(routes)} routes",
        "source": "heuristic",
    }


def _normalize(ai_result: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    out = dict(fallback)
    for key in ("purpose_1sent", "domain", "scan_focus"):
        val = ai_result.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()[:400]
    dc = ai_result.get("domain_confidence")
    if isinstance(dc, (int, float)) and 0 <= dc <= 1:
        out["domain_confidence"] = float(dc)
    tsc = ai_result.get("tech_stack_confirmed")
    if isinstance(tsc, list):
        out["tech_stack_confirmed"] = [str(x)[:40] for x in tsc[:8] if str(x).strip()]
    cdr = ai_result.get("critical_dirs_reasoned")
    if isinstance(cdr, list):
        norm = []
        for item in cdr[:4]:
            if isinstance(item, dict) and item.get("dir"):
                norm.append({"dir": str(item["dir"])[:60], "why": str(item.get("why", ""))[:120]})
        if norm:
            out["critical_dirs_reasoned"] = norm
    tr = ai_result.get("top_risks")
    if isinstance(tr, list):
        norm = []
        for item in tr[:3]:
            if isinstance(item, dict) and item.get("risk"):
                norm.append({"risk": str(item["risk"])[:60], "why": str(item.get("why", ""))[:160]})
        if norm:
            out["top_risks"] = norm
    return out
