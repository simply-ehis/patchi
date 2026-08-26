"""
`p chat` — Unified AI chat with automatic reasoning engine routing.

Usage:
  p chat                          — start interactive chat session
  p chat "what changed?"          — auto-routes to reasoning engine
  p chat "what does auth do?"     — auto-routes to reasoning engine
  p chat "security hotspots"      — auto-routes to reasoning engine
  p chat "explain this code"      — uses AI chat
  p ask "what changed?"           — alias for p chat (backward compatible)

Auto-routing:
  - Questions about changes, imports, layers, hotspots → Reasoning Engine (no AI tokens)
  - Everything else → AI Chat (uses tokens)

Force routing:
  - Prefix with "ai:" to force AI chat:  p chat "ai: explain this"
  - Prefix with "reason:" to force reasoning: p chat "reason: what changed"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con

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
- Be concise but thorough -- prefer bullet points over walls of text
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

    parts.append(
        f"Project: {file_count} files, {route_count} routes, framework: {framework}, health: {health_total}/100"
    )

    # Routes
    if any(w in m_lower for w in ["route", "endpoint", "api", "path"]):
        routes = brain.get("routes", [])
        if routes and isinstance(routes, list):
            samples = []
            for r in routes[:15]:
                if isinstance(r, dict):
                    samples.append(
                        f"  {r.get('method', '?')} {r.get('path', '?')} ({r.get('file', '?')})"
                    )
                else:
                    samples.append(f"  {r}")
            if samples:
                parts.append(f"Routes ({len(routes)} total):\n" + "\n".join(samples[:15]))

    # Findings / issues
    if any(
        w in m_lower
        for w in ["finding", "issue", "vulnerability", "bug", "critical", "high", "error"]
    ):
        issues = brain.get("issues", []) or brain.get("findings", [])
        if issues:
            by_sev = {}
            for f in issues:
                if isinstance(f, dict):
                    sev = f.get("severity", "info")
                    by_sev[sev] = by_sev.get(sev, 0) + 1
            if by_sev:
                sev_str = ", ".join(f"{c} {s}" for s, c in sorted(by_sev.items()))
                parts.append(f"Issues ({len(issues)} total): {sev_str}")
                top = [
                    f
                    for f in issues
                    if isinstance(f, dict) and f.get("severity") in ("critical", "high")
                ][:5]
                for f in top:
                    parts.append(
                        f"  [{f.get('severity', 'info')}] {f.get('file', '')}:{f.get('line', 0)} -- {f.get('message', '')[:80]}"
                    )

    # Security
    if any(w in m_lower for w in ["security", "cve", "secret", "injection", "xss", "sqli", "auth"]):
        sec_str = brain.get("security_str", brain.get("security_report", {}))
        if isinstance(sec_str, dict):
            parts.append(
                f"Security: {sec_str.get('critical', 0)} critical, {sec_str.get('high', 0)} high, {sec_str.get('medium', 0)} medium"
            )

    # Patches / fixes
    if any(w in m_lower for w in ["patch", "fix", "apply", "change", "modify", "edit"]):
        patches = brain.get("patches", [])
        if patches:
            applied = sum(
                1
                for p in patches
                if isinstance(p, dict) and p.get("state") in ("applied", "auto_applied")
            )
            pending = sum(1 for p in patches if isinstance(p, dict) and p.get("state") == "pending")
            parts.append(f"Patches: {applied} applied, {pending} pending")

    # Tests
    if any(w in m_lower for w in ["test", "coverage", "pytest"]):
        test_info = brain.get("test_results", {})
        if test_info:
            parts.append(
                f"Tests: {test_info.get('passed', 0)} passed, {test_info.get('failed', 0)} failed"
            )

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


def _try_explain(message: str, root: Path) -> tuple[bool, str]:
    """Try to answer using the explain knowledge base. Returns (success, formatted_answer)."""
    m_lower = message.lower().strip()

    # Detect explain-like queries
    explain_patterns = [
        "explain", "what is", "what does", "what are", "how does",
        "why is", "tell me about", "describe", "meaning of",
    ]
    is_explain = any(p in m_lower for p in explain_patterns)
    if not is_explain:
        return False, ""

    # Try to extract a finding type from the message
    from patchi.cli.commands.explain_cmd import _EXPLANATIONS

    # Direct match
    for ftype, info in _EXPLANATIONS.items():
        if ftype.replace("_", " ") in m_lower or ftype in m_lower:
            return True, _format_explanation(ftype, info)

    # Keyword match
    keyword_map = {
        "secret": "hardcoded_secret", "password": "hardcoded_secret",
        "sql": "sql_injection", "injection": "sql_injection",
        "xss": "xss", "cross-site": "xss", "script": "xss",
        "csrf": "csrf", "cross-site request": "csrf",
        "header": "missing_security_header", "csp": "missing_security_header",
        "debug": "debug_mode", "hardcoded": "hardcoded_secret",
        "eval": "dangerous_eval", "exec": "dangerous_exec",
        "pickle": "unsafe_deserialization", "yaml": "yaml_load",
        "directory": "directory_traversal", "traversal": "directory_traversal",
    }
    for keyword, ftype in keyword_map.items():
        if keyword in m_lower and ftype in _EXPLANATIONS:
            return True, _format_explanation(ftype, _EXPLANATIONS[ftype])

    # If explain-like but no specific finding, show all
    if "explain" in m_lower and ("findings" in m_lower or "issues" in m_lower or "all" in m_lower):
        output_lines = ["[bold]Security Knowledge Base:[/bold]", ""]
        for ftype, info in _EXPLANATIONS.items():
            output_lines.append(f"  [bold]{info['title']}[/bold] (CWE-{info.get('cwe', '?')})")
            output_lines.append(f"    {info['what']}")
            output_lines.append(f"    Fix: {info['how'].split(chr(10))[0]}")
            output_lines.append("")
        return True, chr(10).join(output_lines)

    return False, ""


def _format_explanation(ftype: str, info: dict) -> str:
    """Format a single explanation for display."""
    lines = [
        f"[bold]{info['title']}[/bold]  [dim](CWE-{info.get('cwe', '?')}, {info.get('severity', '?')})[/dim]",
        "",
        f"[bold]What:[/bold] {info['what']}",
        f"[bold]Why it matters:[/bold] {info['why']}",
        f"[bold]How to fix:[/bold] {info['how'].split(chr(10))[0]}",
    ]
    return chr(10).join(lines)


def _try_reasoning_engine(message: str, root: Path) -> tuple[bool, str]:
    """Try to answer using the reasoning engine. Returns (success, formatted_answer)."""
    from patchi.core.security.reasoning import classify_question, answer_question

    # Check if reasoning can handle this
    category = classify_question(message)

    # For "general" category, check if there are layers to report on
    if category == "general":
        from patchi.core.brain.layered_brain import layers_from_dict
        import json

        path = root / ".patchi" / "memory" / "layers.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                layers = layers_from_dict(data)
                if not layers:
                    return False, ""
            except Exception:
                return False, ""
        else:
            return False, ""

    # Reasoning can handle this
    result = answer_question(message, root)

    # Format the result
    output = []

    # Answer
    output.append("[bold]Reasoning Engine:[/bold]")
    for line in result.answer.split("\n"):
        if line.startswith("==="):
            output.append(f"  [bold yellow]{line}[/bold yellow]")
        elif line.startswith("  "):
            output.append(f"  [dim]{line.strip()}[/dim]")
        elif line.startswith("-"):
            output.append(f"  {line}")
        elif ":" in line:
            parts = line.split(":", 1)
            output.append(f"  [bold]{parts[0]}:[/bold]{parts[1]}")
        else:
            output.append(f"  {line}")
    output.append("")

    # Layers
    if result.layers:
        output.append("[dim]Affected layers: " + ", ".join(sorted(result.layers)[:5]))
        if len(result.layers) > 5:
            output.append(f"  ... and {len(result.layers) - 5} more")
        output.append("[/dim]")
        output.append("")

    # Hotspots table
    if "hotspots" in result.details:
        table = Table(title="Security Hotspots", box=None, show_lines=False)
        table.add_column("Score", style="red")
        table.add_column("Layer", style="cyan")
        table.add_column("Reasons", style="yellow")
        for h in result.details["hotspots"][:10]:
            table.add_row(
                str(h["risk_score"]),
                h["name"],
                ", ".join(h["reasons"][:3]),
            )
        output.append(str(table))
        output.append("")

    # Dependencies
    if "depends" in result.details and result.details["depends"]:
        deps = result.details["depends"]
        output.append(f"[bold]Dependencies:[/bold] {', '.join(deps)}")
        output.append("")

    if "dependents" in result.details and result.details["dependents"]:
        deps = result.details["dependents"]
        output.append(f"[bold]Dependents:[/bold] {', '.join(deps)}")
        output.append("")

    return True, "\n".join(output)


def _print_ai_response(response: str) -> None:
    """Print an AI response with formatting."""
    con.print()
    con.print("[bold #4ADE80]Patchi:[/bold #4ADE80]")
    con.print(Markdown(response))
    con.print()


def _check_force_routing(message: str) -> tuple[str, bool]:
    """Check for forced routing prefixes. Returns (cleaned_message, use_reasoning)."""
    msg = message.strip()
    if msg.lower().startswith("reason:"):
        return msg[7:].strip(), True
    if msg.lower().startswith("ai:"):
        return msg[3:].strip(), False
    return msg, None  # None means auto-route


def _should_use_reasoning(message: str, root: Path) -> bool:
    """Determine if the reasoning engine should handle this query."""
    from patchi.core.security.reasoning import classify_question

    category = classify_question(message)

    # Always use reasoning for these categories
    if category in ("what_changed", "what_does", "what_imports", "imports", "hotspots"):
        return True

    # For routes/layers, use reasoning only if we have layered brain data
    if category in ("routes", "layers"):
        path = root / ".patchi" / "memory" / "layers.json"
        if path.exists():
            return True

    # For general queries, use reasoning if we have data but the question
    # is about the codebase (contains relevant keywords)
    if category == "general":
        keywords = [
            "what", "how", "where", "which", "why", "who",
            "does", "is", "are", "was", "were",
            "import", "depend", "module", "layer", "file",
            "route", "api", "endpoint", "handler",
            "security", "vulnerability", "risk",
        ]
        q = message.lower()
        if any(kw in q for kw in keywords):
            # Check if we have data
            path = root / ".patchi" / "memory" / "layers.json"
            if path.exists():
                return True

    return False


def run(
    message: list[str] | str | None = None,
    json_output: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p chat` and `p ask` (backward compatible)."""
    try:
        from patchi.core.config import require_project_root
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
        if isinstance(message, list):
            message = " ".join(message)

        if not message.strip():
            con.print("[red]Error: no message provided[/red]")
            return

        # Check for forced routing
        clean_msg, force_reason = _check_force_routing(message)

        if force_reason is True:
            # Force reasoning engine
            success, answer = _try_reasoning_engine(clean_msg, r)
            if success:
                if json_output:
                    from patchi.core.security.reasoning import answer_question
                    result = answer_question(clean_msg, r)
                    print(json.dumps(result.to_dict(), indent=2))
                else:
                    con.print()
                    con.print(answer)
                return
            else:
                con.print("[yellow]Reasoning engine couldn't answer this. Falling back to AI...[/yellow]")

        elif force_reason is False:
            # Force AI
            context = _build_injected_context(brain, clean_msg)
            extra = f"\n\nRelevant context:\n{context}" if context else ""
            response = call_ai(config, BASE_PROMPT + extra, clean_msg)
            if not response:
                con.print(
                    "[yellow]No AI configured. Set up with `p key add` or `p model set <model>`.[/yellow]"
                )
                return
            if json_output:
                print(json.dumps({"answer": response, "source": "ai"}, indent=2))
            else:
                _print_ai_response(response)
            return

        else:
            # Auto-route: try reasoning first, then AI
            if _should_use_reasoning(clean_msg, r):
                success, answer = _try_reasoning_engine(clean_msg, r)
                if success:
                    if json_output:
                        from patchi.core.security.reasoning import answer_question
                        result = answer_question(clean_msg, r)
                        print(json.dumps(result.to_dict(), indent=2))
                    else:
                        con.print()
                        con.print(answer)
                    return

            # Fall back to AI
            context = _build_injected_context(brain, clean_msg)
            extra = f"\n\nRelevant context:\n{context}" if context else ""
            response = call_ai(config, BASE_PROMPT + extra, clean_msg)
            if not response:
                con.print(
                    "[yellow]No AI configured. Set up with `p key add` or `p model set <model>`.[/yellow]"
                )
                return
            if json_output:
                print(json.dumps({"answer": response, "source": "ai"}, indent=2))
            else:
                _print_ai_response(response)
            return

    # Interactive mode
    con.print()
    con.print(
        Panel(
            "[bold]Patchi Chat[/bold]  [dim]Type your message, or 'quit' to exit.[/dim]\n"
            "[dim]Ask about findings, routes, security, architecture, or anything else.[/dim]\n"
            "[dim]Prefix with 'reason:' for reasoning engine, 'ai:' for AI chat.[/dim]",
            border_style="#C8621A",
        )
    )
    con.print()

    history = _load_chat_history(r)

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

        # Check for forced routing
        clean_msg, force_reason = _check_force_routing(user_input)

        if force_reason is True:
            # Force reasoning
            success, answer = _try_reasoning_engine(clean_msg, r)
            if success:
                con.print()
                con.print(answer)
                history.append({"role": "user", "content": user_input})
                history.append({"role": "assistant", "content": f"[Reasoning Engine]\n{answer}"})
                _save_chat_history(r, history)
                continue
            else:
                con.print("[yellow]Reasoning engine couldn't handle this. Trying AI...[/yellow]")

        elif force_reason is False:
            # Force AI
            context = _build_injected_context(brain, clean_msg)
            extra = f"\n\nRelevant context:\n{context}" if context else ""
            full_system = BASE_PROMPT + extra

            history_text = ""
            for msg in history[-10:]:
                role = "Developer" if msg["role"] == "user" else "Patchi"
                history_text += f"{role}: {msg['content']}\n"

            full_prompt = clean_msg
            if history_text:
                full_prompt = f"Previous conversation:\n{history_text}\nCurrent question: {clean_msg}"

            response = call_ai(config, full_system, full_prompt)
            if not response:
                response = "I don't have an AI model configured. Set up with `p key add`."

            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": response})
            history[:] = history[-MAX_HISTORY:]
            _save_chat_history(r, history)

            _print_ai_response(response)
            continue

        else:
            # Auto-route
            if _should_use_reasoning(clean_msg, r):
                success, answer = _try_reasoning_engine(clean_msg, r)
                if success:
                    con.print()
                    con.print(answer)
                    history.append({"role": "user", "content": user_input})
                    history.append({"role": "assistant", "content": f"[Reasoning Engine]\n{answer}"})
                    _save_chat_history(r, history)
                    continue

            # Fall back to AI
            context = _build_injected_context(brain, clean_msg)
            extra = f"\n\nRelevant context:\n{context}" if context else ""
            full_system = BASE_PROMPT + extra

            history_text = ""
            for msg in history[-10:]:
                role = "Developer" if msg["role"] == "user" else "Patchi"
                history_text += f"{role}: {msg['content']}\n"

            full_prompt = clean_msg
            if history_text:
                full_prompt = f"Previous conversation:\n{history_text}\nCurrent question: {clean_msg}"

            response = call_ai(config, full_system, full_prompt)
            if not response:
                response = "I don't have an AI model configured. Set up with `p key add`."

            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": response})
            history[:] = history[-MAX_HISTORY:]
            _save_chat_history(r, history)

            _print_ai_response(response)
