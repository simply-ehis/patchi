"""
`p chat` — Interactive AI chat with Patchi.

Usage:
  p chat                    — start interactive chat session
  p chat "what is this?"    — send a single message and get response

Talks to the configured AI (Ollama, API key, or AI Horde).
Maintains conversation context across messages.

Context is dynamically enriched based on what you ask about:
- Findings, issues → injects recent scanner findings
- Routes, endpoints → injects route map
- Security, CVE → injects security scan results
- Patches, fixes → injects patch history
- Tests → injects test results
- Health → injects health breakdown
"""

from __future__ import annotations
from patchi.cli.console import con

import json
from pathlib import Path

from rich.markdown import Markdown
from rich.panel import Panel

from patchi.core.config import require_project_root

MAX_HISTORY = 50
CHAT_HISTORY_FILE = ".patchi/memory/chat_history.json"

import logging
_log = logging.getLogger("patchi.cli.chat_cmd")

def _load_chat_history(root: Path) -> list[dict]:
    path = root / CHAT_HISTORY_FILE
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            _log.warning("_load_chat_history failed: %s", e)
    return []

def _save_chat_history(root: Path, history: list[dict]) -> None:
    path = root / CHAT_HISTORY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(history[-MAX_HISTORY:], indent=2), encoding="utf-8")

BASE_PROMPT = """You are Patchi, an intelligent code assistant integrated into a project analysis tool.

You are helping the developer understand their project and its issues.

Your role:
- Explain code issues in simple, clear language the developer can understand
- When asked about a finding, explain what it means, why it matters, and how to fix it
- Help the developer understand their architecture and codebase
- Be concise but thorough — prefer bullet points over walls of text
- If you don't know something specific about the code, say so honestly

You are NOT a general-purpose AI assistant. You are a specialized code assistant for the project in the current directory."""

def _build_injected_context(brain: dict, message: str) -> str:
    """Build relevant context from the brain based on what the user is asking about."""
    m_lower = message.lower()
    parts = []

    # Project overview
    file_count = brain.get("file_count", 0)
    framework = brain.get("framework", "Unknown")
    route_count = brain.get("route_count", 0)
    health = brain.get("health_score", {})
    health_total = health.get("total", 0) if isinstance(health, dict) else health

    parts.append(f"Project: {file_count} files, {route_count} routes, framework: {framework}, health: {health_total}/100")

    # Routes
    if any(w in m_lower for w in ["route", "endpoint", "api", "path"]):
        routes = brain.get("routes", [])
        if routes and isinstance(routes, list):
            samples = []
            for r in routes[:15]:
                if isinstance(r, dict):
                    samples.append(f"  {r.get('method', '?')} {r.get('path', '?')} ({r.get('file', '?')})")
                else:
                    samples.append(f"  {r}")
            if samples:
                parts.append(f"Routes ({len(routes)} total):\n" + "\n".join(samples[:15]))

    # Findings / issues
    if any(w in m_lower for w in ["finding", "issue", "vulnerability", "bug", "critical", "high", "error"]):
        issues = brain.get("issues", []) or brain.get("findings", [])
        if issues:
            by_sev: dict[str, int] = {}
            for f in issues:
                if isinstance(f, dict):
                    sev = f.get("severity", "info")
                    by_sev[sev] = by_sev.get(sev, 0) + 1
            if by_sev:
                sev_str = ", ".join(f"{c} {s}" for s, c in sorted(by_sev.items()))
                parts.append(f"Issues ({len(issues)} total): {sev_str}")
                top = [f for f in issues if isinstance(f, dict) and f.get("severity") in ("critical", "high")][:5]
                for f in top:
                    parts.append(f"  [{f.get('severity','info')}] {f.get('file','')}:{f.get('line',0)} — {f.get('message','')[:80]}")

    # Security
    if any(w in m_lower for w in ["security", "cve", "secret", "injection", "xss", "sqli", "auth"]):
        sec_str = brain.get("security_str", brain.get("security_report", {}))
        if isinstance(sec_str, dict):
            parts.append(f"Security: {sec_str.get('critical', 0)} critical, {sec_str.get('high', 0)} high, {sec_str.get('medium', 0)} medium")

    # Patches / fixes
    if any(w in m_lower for w in ["patch", "fix", "apply", "change", "modify", "edit"]):
        patches = brain.get("patches", [])
        if patches:
            applied = sum(1 for p in patches if isinstance(p, dict) and p.get("state") in ("applied", "auto_applied"))
            pending = sum(1 for p in patches if isinstance(p, dict) and p.get("state") == "pending")
            parts.append(f"Patches: {applied} applied, {pending} pending")

    # Tests
    if any(w in m_lower for w in ["test", "coverage", "pytest"]):
        test_info = brain.get("test_results", {})
        if test_info:
            parts.append(f"Tests: {test_info.get('passed', 0)} passed, {test_info.get('failed', 0)} failed")

    # Dead code / architecture
    if any(w in m_lower for w in ["dead", "unused", "circular", "import", "dependency", "dep"]):
        dead = brain.get("dead_files", [])
        circ = brain.get("circular_dependencies", [])
        if dead:
            parts.append(f"Dead files ({len(dead)}): {', '.join(str(d)[:40] for d in dead[:8])}")
        if circ:
            parts.append(f"Circular dependencies ({len(circ)})")

    # Blast radius
    if any(w in m_lower for w in ["break", "affect", "impact", "change", "modify"]):
        import_graph = brain.get("import_graph", {})
        if import_graph:
            node_count = len(import_graph.get("nodes", []))
            edge_count = len(import_graph.get("edges", {}))
            parts.append(f"Import graph: {node_count} nodes, {edge_count} edges")

    return "\n".join(parts) if parts else ""

def run(
    message: str | None = None,
    root: Path | None = None,
) -> None:
    """Entry point for `p chat [message]`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg
    from patchi.core import memory as mem
    from patchi.core.ai.client import call_ai

    config = cfg.load(r)
    brain = mem.get_brain(r)

    # Single message mode
    if message:
        context = _build_injected_context(brain, message)
        extra = f"\n\nRelevant context:\n{context}" if context else ""
        response = call_ai(config, BASE_PROMPT + extra, message)
        if not response:
            con.print(
                "[yellow]No AI configured. Set up with `p key add` or `p model set <model>`.[/yellow]"
            )
            return
        con.print()
        con.print(Markdown(response))
        con.print()
        return

    # Interactive mode
    con.print()
    con.print(
        Panel(
            "[bold]Patchi Chat[/bold]  [dim]Type your message, or 'quit' to exit.[/dim]\n"
            "[dim]Ask about findings, routes, security, patches, tests, or architecture.[/dim]",
            border_style="#C8621A",
        )
    )
    con.print()

    history: list[dict] = _load_chat_history(r)

    while True:
        try:
            user_input = con.input("[bold #C8621A]You:[/bold #C8621A] ").strip()
        except (EOFError, KeyboardInterrupt):
            _save_chat_history(r, history)
            con.print("\n[dim]Chat ended.[/dim]")
            return

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            _save_chat_history(r, history)
            con.print("[dim]Chat ended.[/dim]")
            return

        # Build context based on what they're asking about
        context = _build_injected_context(brain, user_input)
        extra = f"\n\nRelevant context:\n{context}" if context else ""

        full_system = BASE_PROMPT + extra

        # Build prompt with history
        history_text = ""
        for msg in history[-10:]:
            role = "Developer" if msg["role"] == "user" else "Patchi"
            history_text += f"{role}: {msg['content']}\n"

        full_prompt = user_input
        if history_text:
            full_prompt = f"Previous conversation:\n{history_text}\nCurrent question: {user_input}"

        response = call_ai(config, full_system, full_prompt)

        if not response:
            response = (
                "I don't have an AI model configured right now. "
                "Set up an AI key with `p key add` or use Ollama with `p model set <model>`."
            )

        history.append({"role": "user", "content": user_input})
        history.append({"role": "assistant", "content": response})
        history[:] = history[-MAX_HISTORY:]
        _save_chat_history(r, history)

        con.print()
        con.print("[bold #4ADE80]Patchi:[/bold #4ADE80]")
        con.print(Markdown(response))
        con.print()