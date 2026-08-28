"""Chat API — The Brain. Uses the same Orchestrator as CLI `p chat`.

This is NOT a thin LLM wrapper — it has full access to:
  - Read/write any file in the project
  - Run any CLI command
  - Spawn any agent (security, testing, fixing, etc.)
  - Access the full brain/memory state
  - Execute tools from the tool registry
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/chat")
_log = logging.getLogger("patchi.web.chat")


def _build_context(brain: dict, message: str) -> str:
    """Build relevant context from brain data based on the user's question."""
    m_lower = message.lower()
    parts = []

    file_count = brain.get("file_count", 0)
    route_count = brain.get("route_count", 0)
    framework = brain.get("framework", "Unknown")
    health = brain.get("health_score", {})
    health_total = health.get("total", 0) if isinstance(health, dict) else health
    parts.append(
        f"Project: {file_count} files, {route_count} routes, framework: {framework}, health: {health_total}/100"
    )

    if any(
        w in m_lower
        for w in ["finding", "issue", "vulnerability", "bug", "critical", "high", "error"]
    ):
        issues = brain.get("issues", []) or brain.get("findings", [])
        if issues and isinstance(issues, list):
            by_sev: dict[str, int] = {}
            for f in issues:
                sev = f.get("severity", "info") if isinstance(f, dict) else "info"
                by_sev[sev] = by_sev.get(sev, 0) + 1
            if by_sev:
                parts.append(
                    f"Issues ({len(issues)} total): {', '.join(f'{c} {s}' for s, c in sorted(by_sev.items()))}"
                )
            top = [
                f
                for f in issues
                if isinstance(f, dict) and f.get("severity") in ("critical", "high")
            ][:5]
            for f in top:
                parts.append(
                    f"  [{f['severity']}] {f.get('file', '')}:{f.get('line', 0)} — {f.get('message', '')[:80]}"
                )

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
            parts.append(
                f"Security: {sec.get('critical', 0)}c, {sec.get('high', 0)}h, {sec.get('medium', 0)}m"
            )

    if any(w in m_lower for w in ["patch", "fix", "change"]):
        patches = brain.get("patches", [])
        if patches and isinstance(patches, list):
            applied = sum(
                1
                for p in patches
                if isinstance(p, dict) and p.get("state") in ("applied", "auto_applied")
            )
            pending = sum(1 for p in patches if isinstance(p, dict) and p.get("state") == "pending")
            parts.append(f"Patches: {applied} applied, {pending} pending")

    if any(w in m_lower for w in ["test", "coverage"]):
        tests = brain.get("test_results", {})
        if tests:
            parts.append(f"Tests: {tests.get('passed', 0)} passed, {tests.get('failed', 0)} failed")

    return "\n".join(parts) if parts else ""


@router.post("")
async def chat_message(request: Request) -> JSONResponse:
    """Process a chat message through the Orchestrator (same as CLI `p chat`)."""
    body = await request.json()
    message = body.get("message", "")

    if not message:
        return JSONResponse({"ok": False, "error": "No message"}, status_code=400)

    root = request.app.state.root

    try:
        from patchi.core.ai.orchestrator import Orchestrator
        from patchi.web.ws import manager

        import asyncio

        loop = asyncio.get_event_loop()
        events = []

        def on_event(payload: dict) -> None:
            events.append(payload)
            try:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast(payload["event"], payload["data"]), loop
                )
            except Exception:
                pass

        def on_progress(msg: str) -> None:
            try:
                asyncio.run_coroutine_threadsafe(
                    manager.broadcast("agent.progress", {
                        "agent": "chat",
                        "progress_pct": 0,
                        "current_file": msg,
                    }), loop
                )
            except Exception:
                pass

        orchestrator = Orchestrator(root, on_event=on_event, on_progress=on_progress)

        # Check for direct file operations (same as CLI)
        read_patterns = ["read ", "show ", "cat ", "what's in ", "what is in ", "open ", "display "]
        if any(message.lower().startswith(p) for p in read_patterns):
            file_path = message
            for p in read_patterns:
                if file_path.lower().startswith(p):
                    file_path = file_path[len(p):].strip()
                    break
            content = orchestrator.read_file(file_path)
            if not content.startswith("ERROR:"):
                return JSONResponse({"ok": True, "response": f"📄 **{file_path}**\n\n```\n{content}\n```"})
            else:
                return JSONResponse({"ok": True, "response": content})

        # Check for command execution
        if message.lower().startswith(("run ", "exec ")):
            command = message
            for p in ["run ", "exec "]:
                if command.lower().startswith(p):
                    command = command[len(p):].strip()
                    break
            result = orchestrator.run_command(command)
            if result.get("success"):
                stdout = result.get("stdout", "Command succeeded")
                return JSONResponse({"ok": True, "response": f"✅ Command succeeded\n\n```\n{stdout}\n```"})
            else:
                error = result.get("error", result.get("stderr", "unknown"))
                return JSONResponse({"ok": True, "response": f"❌ Command failed: {error}"})

        # Check for agent spawning
        spawn_patterns = ["spawn ", "run agent ", "use agent ", "activate "]
        if any(message.lower().startswith(p) for p in spawn_patterns):
            agent_type = message
            for p in spawn_patterns:
                if agent_type.lower().startswith(p):
                    agent_type = agent_type[len(p):].strip()
                    break
            for atype in ["security", "scanner", "proactive", "council", "smart"]:
                if atype in agent_type.lower():
                    result = orchestrator.spawn_agent(atype, goal=message)
                    if result.get("success"):
                        return JSONResponse({
                            "ok": True,
                            "response": f"🤖 Agent `{atype}` completed\n\n```json\n{json.dumps(result.get('result', {}), indent=2, default=str)[:2000]}\n```"
                        })
                    else:
                        return JSONResponse({"ok": True, "response": f"❌ Agent failed: {result.get('error', 'unknown')}"})

        # Default: LLM-powered orchestration (same as CLI)
        brain = __import__("patchi.core.memory", fromlist=["get_brain"]).get_brain(root)
        context = _build_context(brain, message)

        system_prompt = """You are Patchi, the intelligent brain that controls the entire Patchi system.

You are NOT just a chat interface — you ARE the orchestrator with direct control over:
- Reading and writing files in the project
- Running any CLI command (scan, test, fix, etc.)
- Spawning specialized agents (security, testing, fixing, etc.)
- Accessing the full brain/memory state
- Making decisions based on context

When the user asks you to DO something, determine what tools/agents are needed.
When the user asks about files, you can read and explain them.
You have full control. Use it wisely."""
        if context:
            system_prompt += f"\n\nRelevant context:\n{context}"

        from patchi.core.config import load as load_config
        from patchi.core.ai.client import call_ai

        config = load_config(root)
        response = call_ai(config, system_prompt, message, max_tokens=1500)

        if not response:
            response = "I don't have an AI model configured. Set up with `p key add` or `p model set <model>`."

        return JSONResponse({"ok": True, "response": response})

    except Exception as e:
        _log.error("Chat error: %s", e)
        return JSONResponse({
            "ok": True,
            "response": f"Error: {e}. Make sure an AI key is configured with `p key add`.",
        })
