"""Chat API — AI chat with smart brain context injection."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/chat")

BASE_PROMPT = """You are Patchi, a security assistant. You help developers understand and fix security issues.

Answer concisely. If asked about specific findings, explain what the issue is and how to fix it.
Use markdown for formatting."""


def _build_context(brain: dict, message: str) -> str:
    """Build relevant context from brain data based on the user's question."""
    m_lower = message.lower()
    parts = []

    file_count = brain.get("file_count", 0)
    route_count = brain.get("route_count", 0)
    framework = brain.get("framework", "Unknown")
    health = brain.get("health_score", {})
    health_total = health.get("total", 0) if isinstance(health, dict) else health
    parts.append(f"Project: {file_count} files, {route_count} routes, framework: {framework}, health: {health_total}/100")

    if any(w in m_lower for w in ["finding", "issue", "vulnerability", "bug", "critical", "high", "error"]):
        issues = brain.get("issues", []) or brain.get("findings", [])
        if issues and isinstance(issues, list):
            by_sev: dict[str, int] = {}
            for f in issues:
                sev = f.get("severity", "info") if isinstance(f, dict) else "info"
                by_sev[sev] = by_sev.get(sev, 0) + 1
            if by_sev:
                parts.append(f"Issues ({len(issues)} total): {', '.join(f'{c} {s}' for s, c in sorted(by_sev.items()))}")
            top = [f for f in issues if isinstance(f, dict) and f.get("severity") in ("critical", "high")][:5]
            for f in top:
                parts.append(f"  [{f['severity']}] {f.get('file','')}:{f.get('line',0)} — {f.get('message','')[:80]}")

    if any(w in m_lower for w in ["route", "endpoint", "api", "path"]):
        routes = brain.get("routes", [])
        if routes and isinstance(routes, list):
            samples = []
            for r in routes[:15]:
                if isinstance(r, dict):
                    samples.append(f"  {r.get('method', '?')} {r.get('path', '?')}")
                else:
                    samples.append(f"  {r}")
            if samples:
                parts.append(f"Routes ({len(routes)} total):\n" + "\n".join(samples[:15]))

    if any(w in m_lower for w in ["security", "cve", "secret", "injection", "xss", "sqli"]):
        sec = brain.get("security_report", brain.get("security_str", {}))
        if isinstance(sec, dict):
            parts.append(f"Security: {sec.get('critical', 0)}c, {sec.get('high', 0)}h, {sec.get('medium', 0)}m")

    if any(w in m_lower for w in ["patch", "fix", "change"]):
        patches = brain.get("patches", [])
        if patches and isinstance(patches, list):
            applied = sum(1 for p in patches if isinstance(p, dict) and p.get("state") in ("applied", "auto_applied"))
            pending = sum(1 for p in patches if isinstance(p, dict) and p.get("state") == "pending")
            parts.append(f"Patches: {applied} applied, {pending} pending")

    if any(w in m_lower for w in ["test", "coverage"]):
        tests = brain.get("test_results", {})
        if tests:
            parts.append(f"Tests: {tests.get('passed', 0)} passed, {tests.get('failed', 0)} failed")

    return "\n".join(parts) if parts else ""


@router.post("")
async def chat_message(request: Request) -> JSONResponse:
    body = await request.json()
    message = body.get("message", "")

    if not message:
        return JSONResponse({"ok": False, "error": "No message"}, status_code=400)

    root = request.app.state.root
    from patchi.core import config as cfg
    from patchi.core import memory as mem

    try:
        config = cfg.load(root)
    except Exception:
        config = {}

    brain = mem.get_brain(root)

    context = _build_context(brain, message)
    system = f"{BASE_PROMPT}\n\n{context}" if context else BASE_PROMPT

    try:
        from patchi.core.ai.client import call_ai

        response = call_ai(config, system, message, max_tokens=1000)
        return JSONResponse(
            {
                "ok": True,
                "response": response
                or "I couldn't generate a response. Make sure an AI key is configured with 'p key add'.",
            }
        )
    except Exception as e:
        return JSONResponse(
            {
                "ok": True,
                "response": f"AI not available: {e}. Run 'p key add' to configure an AI provider.",
            }
        )
