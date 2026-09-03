"""
`p chat` — The Brain. The single intelligence that controls everything.

The chat IS the orchestrator. It has direct access to:
  - Read/write any file in the project
  - Run any CLI command
  - Spawn any agent (security, testing, fixing, etc.)
  - Access the full brain/memory state
  - Make decisions based on context

Usage:
  p chat                              — interactive brain session
  p chat "scan this project"          — executes security scan
  p chat "what's in src/auth.py"      — reads and explains the file
  p chat "fix all critical findings"  — scans and fixes
  p chat "run tests and check coverage" — multi-step orchestration
  p chat "write a rate limiter"       — creates the file
  p ask "what changed?"               — backward-compatible alias
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from patchi.cli.console import con

MAX_HISTORY = 50
CHAT_HISTORY_FILE = ".patchi/memory/chat_history.json"


_log = logging.getLogger("patchi.cli.chat_cmd")


# ── History persistence ────────────────────────────────────────────────

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


# ── System prompt ──────────────────────────────────────────────────────

BASE_PROMPT = """You are Patchi, the intelligent brain that controls the entire Patchi system.

You are NOT just a chat interface — you ARE the orchestrator with direct control over:
- Reading and writing files in the project
- Running any CLI command (scan, test, fix, etc.)
- Spawning specialized agents (security, testing, fixing, etc.)
- Accessing the full brain/memory state
- Making decisions based on context

When the user asks you to DO something, you should:
1. Determine what tools/agents are needed
2. Execute them using the brain's capabilities
3. Report results with context

When the user asks about files, you can:
- Read the file contents directly
- Explain what the code does
- Suggest improvements
- Write changes if asked

You have full control. Use it wisely."""


# ── Context injection ──────────────────────────────────────────────────

def _build_injected_context(brain: dict, message: str, root=None) -> str:
    """Build rich context from the brain using BrainContext for deeper understanding."""
    m_lower = message.lower()
    parts = []

    # Try to load BrainContext for richer context
    ctx = None
    if root:
        try:
            from patchi.core.brain.brain_context import get_brain_context
            ctx = get_brain_context(root)
        except Exception as _exc:
            _log.debug('suppressed: %s', _exc)

    if ctx and ctx.is_loaded():
        # Use BrainContext for rich context injection
        parts.append(ctx.get_context_for_prompt(max_chars=2000))
    else:
        # Fallback to basic brain dict
        file_count = brain.get("file_count", 0)
        framework = brain.get("framework", "Unknown")
        route_count = brain.get("route_count", 0)
        health = brain.get("health_score", {})
        health_total = health.get("total", 0) if isinstance(health, dict) else health
        parts.append(f"Project: {file_count} files, {route_count} routes, framework: {framework}, health: {health_total}/100")

    # Finding-specific context
    if any(w in m_lower for w in ["finding", "issue", "vulnerability", "bug", "critical", "high", "error"]):
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
                top = [f for f in issues if isinstance(f, dict) and f.get("severity") in ("critical", "high")][:5]
                for f in top:
                    parts.append(f"  [{f.get('severity', 'info')}] {f.get('file', '')}:{f.get('line', 0)} -- {f.get('message', '')[:80]}")

    return "\n".join(parts) if parts else ""


# ── Force routing ──────────────────────────────────────────────────────

def _check_force_routing(message: str) -> tuple[str, str | None]:
    """Check for forced routing prefixes. Returns (cleaned_message, force_mode)."""
    msg = message.strip()
    if msg.lower().startswith("reason:"):
        return msg[7:].strip(), "reasoning"
    if msg.lower().startswith("ai:"):
        return msg[3:].strip(), "ai"
    if msg.lower().startswith("tool:"):
        return msg[5:].strip(), "tool"
    return msg, None


# ── Explain All ────────────────────────────────────────────────────────────

def _show_explain_all() -> None:
    """Show the full security knowledge base in a formatted table."""
    from rich.table import Table

    from patchi.cli.commands.explain_cmd import _EXPLANATIONS

    con.print()
    con.print("[bold #C8621A]Security Knowledge Base[/bold #C8621A]")
    con.print("[dim]Complete reference for all security finding types.[/dim]")
    con.print()

    table = Table(show_header=True, header_style="bold #C8621A", box=None)
    table.add_column("Type", style="cyan", min_width=25)
    table.add_column("Title", style="white", min_width=25)
    table.add_column("Severity", width=10)
    table.add_column("CWE", width=12)
    table.add_column("What", max_width=50)
    table.add_column("How to Fix", max_width=40)

    severity_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "dim",
    }

    for ftype, info in sorted(_EXPLANATIONS.items()):
        sev = info.get("severity", "?")
        color = severity_colors.get(sev, "white")
        table.add_row(
            ftype,
            info.get("title", "?"),
            f"[{color}]{sev}[/{color}]",
            info.get("cwe", "?"),
            info.get("what", "?")[:50],
            info.get("how", "?").split("\n")[0][:40],
        )

    con.print(table)
    con.print()
    con.print(f"[dim]{len(_EXPLANATIONS)} finding types in knowledge base.[/dim]")
    con.print("[dim]Use `p chat 'explain sql injection'` for detailed info on any type.[/dim]")
    con.print()


# ── Process message through the Brain ─────────────────────────────────

def _process_message(
    message: str,
    root: Path,
    config: dict,
    brain_state: dict,
    json_output: bool = False,
    history: list[dict] | None = None,
    stream: bool = False,
) -> str:
    """Process a message using the Brain as the central intelligence."""
    from patchi.core.ai.client import call_ai
    from patchi.core.ai.orchestrator import Orchestrator

    clean_msg, force_mode = _check_force_routing(message)

    # Create brain instance with appropriate progress callback
    if stream:
        # Real-time streaming progress with rich formatting
        _tool_count = [0]
        _step_start = [0]

        def on_progress(msg):
            import time as _time
            if "Executing" in msg:
                _tool_count[0] += 1
                _step_start[0] = _time.monotonic()
                tool_name = msg.replace("Executing ", "").replace("...", "")
                con.print(f"  [bold cyan]⟳ Step {_tool_count[0]}:[/bold cyan] [bold]{tool_name}[/bold]")
            elif "Spawning" in msg:
                con.print(f"  [bold magenta]🤖 {msg}[/bold magenta]")
            elif "Planning" in msg or "Understanding" in msg:
                con.print(f"  [bold yellow]🧠 {msg}[/bold yellow]")
            else:
                con.print(f"  [dim]{msg}[/dim]")

        def on_event(payload: dict):
            ev = payload.get("event", "")
            data = payload.get("data", {})
            if ev == "orchestrator.planned":
                steps = data.get("steps", 0)
                reasoning = data.get("reasoning", "")
                con.print(f"  [bold green]📋 Plan:[/bold green] {steps} steps")
                if reasoning:
                    con.print(f"  [dim]{reasoning[:100]}{'...' if len(reasoning) > 100 else ''}[/dim]")
            elif ev == "orchestrator.completed":
                success = data.get("success", False)
                findings = data.get("findings", 0)
                icon = "[green]✓[/green]" if success else "[red]✗[/red]"
                con.print(f"  {icon} [bold]Orchestration complete[/bold]")
                if findings:
                    con.print(f"  [dim]Findings: {findings}[/dim]")
            elif ev == "security.finding":
                sev = data.get("severity", "?").upper()
                desc = data.get("description", data.get("type", ""))
                con.print(f"    [red][{sev}][/red] {desc[:80]}")
            elif ev == "test.suite.completed":
                passed = data.get("passed", 0)
                failed = data.get("failed", 0)
                con.print(f"    [green]Tests: {passed} passed[/green], [red]{failed} failed[/red]")
            elif ev == "agent.progress":
                pct = data.get("progress_pct", 0)
                current = data.get("current_file", "")
                if current and current not in ["planning", "done"]:
                    con.print(f"    [dim]→ {current} ({pct}%)[/dim]")
    else:
        def on_progress(msg):
            con.print(f"  [dim]{msg}[/dim]")
        def on_event(payload: dict):
            pass

    orchestrator = Orchestrator(root, on_progress=on_progress, on_event=on_event)

    # ── File operations (direct brain access) ──

    # Check if user wants to read a file
    read_patterns = ["read ", "show ", "cat ", "what's in ", "what is in ", "open ", "display "]
    if any(clean_msg.lower().startswith(p) for p in read_patterns):
        file_path = clean_msg
        for p in read_patterns:
            if file_path.lower().startswith(p):
                file_path = file_path[len(p):].strip()
                break

        content = orchestrator.read_file(file_path)
        if not content.startswith("ERROR:"):
            con.print(f"\n[bold]📄 {file_path}[/bold]\n")
            con.print(f"```python\n{content}\n```")
            return f"[File: {file_path}]\n{content}"
        else:
            con.print(f"[yellow]{content}[/yellow]")
            return content

    # Check if user wants to write a file
    write_patterns = ["write ", "create ", "save ", "make "]
    if any(clean_msg.lower().startswith(p) for p in write_patterns):
        # Extract file path and content
        parts = clean_msg.split(":", 1) if ":" in clean_msg else clean_msg.split(" to ", 1)
        if len(parts) == 2:
            file_path = parts[0]
            for p in write_patterns:
                if file_path.lower().startswith(p):
                    file_path = file_path[len(p):].strip()
                    break
            content = parts[1].strip()

            result = orchestrator.write_file(file_path, content)
            if result.get("success"):
                con.print(f"\n[green]✓ Written {result['size']} bytes to {file_path}[/green]")
                return f"[Written: {file_path}]"
            else:
                con.print(f"[red]Failed: {result.get('error', 'unknown')}[/red]")
                return f"Failed: {result.get('error', 'unknown')}"

    # ── Command execution ──
    if clean_msg.lower().startswith("run ") or clean_msg.lower().startswith("exec "):
        command = clean_msg
        for p in ["run ", "exec "]:
            if command.lower().startswith(p):
                command = command[len(p):].strip()
                break

        result = orchestrator.run_command(command)
        if result.get("success"):
            con.print("\n[green]✓ Command succeeded[/green]")
            if result.get("stdout"):
                con.print(f"```\n{result['stdout']}\n```")
            return result.get("stdout", "Command succeeded")
        else:
            con.print(f"[red]Command failed: {result.get('error', result.get('stderr', 'unknown'))}[/red]")
            return f"Command failed: {result.get('error', result.get('stderr', 'unknown'))}"

    # ── Agent spawning ──
    spawn_patterns = ["spawn ", "run agent ", "use agent ", "activate "]
    if any(clean_msg.lower().startswith(p) for p in spawn_patterns):
        agent_type = clean_msg
        for p in spawn_patterns:
            if agent_type.lower().startswith(p):
                agent_type = agent_type[len(p):].strip()
                break

        # Extract agent type from the message
        for atype in ["security", "scanner", "proactive", "council", "smart"]:
            if atype in agent_type.lower():
                con.print(f"\n[bold cyan]🤖 Spawning {atype} agent...[/bold cyan]\n")
                result = orchestrator.spawn_agent(atype, goal=clean_msg)
                if result.get("success"):
                    con.print("[green]✓ Agent completed[/green]")
                    return json.dumps(result.get("result", {}), indent=2, default=str)[:2000]
                else:
                    con.print(f"[red]Agent failed: {result.get('error', 'unknown')}[/red]")
                    return f"Agent failed: {result.get('error', 'unknown')}"

    # ── LLM-powered orchestration (default) ──

    # Build context
    context = _build_injected_context(brain_state, clean_msg, root=root)
    extra = f"\n\nRelevant context:\n{context}" if context else ""

    # Build conversation history
    history_text = ""
    if history:
        for msg in history[-10:]:
            role = "Developer" if msg["role"] == "user" else "Brain"
            history_text += f"{role}: {msg['content']}\n"

    full_prompt = clean_msg
    if history_text:
        full_prompt = f"Previous conversation:\n{history_text}\nCurrent question: {clean_msg}"

    # Get AI response
    response = call_ai(config, BASE_PROMPT + extra, full_prompt)
    if not response:
        response = "I don't have an AI model configured. Set up with `p key add` or `p model set <model>`."

    con.print()
    con.print("[bold #4ADE80]Patchi:[/bold #4ADE80]")
    con.print(Markdown(response))
    con.print()

    return response


# ── Help commands ──────────────────────────────────────────────────────

def _print_help():
    """Print help information."""
    con.print(Panel(
        "[bold]Patchi Chat — The Brain[/bold]\n\n"
        "[bold]Direct File Access:[/bold]\n"
        "  [cyan]read[/cyan] src/auth.py          — read and explain a file\n"
        "  [cyan]write[/cyan] src/utils.py:code   — create/overwrite a file\n\n"
        "[bold]Command Execution:[/bold]\n"
        "  [cyan]run[/cyan] pytest tests/          — run any shell command\n"
        "  [cyan]exec[/cyan] ruff check src/      — execute a command\n\n"
        "[bold]Agent Spawning:[/bold]\n"
        "  [cyan]spawn[/cyan] security             — run security scan\n"
        "  [cyan]spawn[/cyan] council              — multi-persona deliberation\n"
        "  [cyan]spawn[/cyan] smart                — goal-driven smart agent\n\n"
        "[bold]Natural Language:[/bold]\n"
        "  [cyan]scan[/cyan] this project          — security scan\n"
        "  [cyan]fix[/cyan] critical findings      — scan + fix pipeline\n"
        "  [cyan]test[/cyan] and check coverage    — run tests\n"
        "  [cyan]what's in[/cyan] src/auth.py      — read file\n\n"
        "[bold]Commands:[/bold]\n"
        "  [green]tools[/green]    — list available tools\n"
        "  [green]council[/green]  — show council/persona info\n"
        "  [green]history[/green]  — show chat history\n"
        "  [green]help[/green]     — this help\n"
        "  [green]clear[/green]    — clear chat history\n\n"
        "[bold]Forced Routing:[/bold]\n"
        "  [yellow]reason:[/yellow] what changed?       — force reasoning engine\n"
        "  [yellow]ai:[/yellow] explain this code       — force AI chat\n"
        "  [yellow]tool:[/yellow] scan_vulnerabilities  — force tool execution\n",
        border_style="#C8621A",
    ))


def _print_tools():
    """Print available tools."""
    try:
        from patchi.core.ai.tools.registry import get_tool_registry
        registry = get_tool_registry()

        table = Table(title="Available Tools", box=None, show_lines=False)
        table.add_column("Tool", style="cyan", min_width=20)
        table.add_column("Description", style="white")
        table.add_column("Category", style="yellow")

        categories = {
            "scan": ["analyze_project", "scan_vulnerabilities", "scan_project"],
            "test": ["run_tests", "generate_tests", "browser_test", "screenshot", "visual_regression"],
            "fix": ["generate_fix", "apply_patch", "verify_fix", "rollback_patch"],
            "attack": ["attack_simulate", "red_team"],
            "stress": ["stress_test"],
            "knowledge": ["ask_brain", "explain_layer", "impact_analysis", "why_file_matters"],
            "compliance": ["check_compliance"],
            "code": ["write_file", "generate_code"],
        }

        tool_to_cat = {}
        for cat, tools in categories.items():
            for t in tools:
                tool_to_cat[t] = cat

        for tool in registry.list_tools():
            table.add_row(
                tool.name,
                tool.description[:60] + "..." if len(tool.description) > 60 else tool.description,
                tool_to_cat.get(tool.name, "other"),
            )

        con.print(table)
    except Exception as e:
        con.print(f"[red]Failed to load tools: {e}[/red]")


def _print_council_info(root: Path):
    """Print council/persona information."""
    try:
        from patchi.core.brain.personas.base import list_personas

        personas = list_personas()
        con.print(f"\n[bold]🏛️ Council — {len(personas)} Personas[/bold]\n")

        table = Table(box=None, show_lines=False)
        table.add_column("Persona", style="cyan", min_width=20)
        table.add_column("Style", style="yellow")
        table.add_column("Focus", style="white")

        style_names = {
            "aggressive": "🔴 Aggressive",
            "cautious": "🟡 Cautious",
            "balanced": "🟢 Balanced",
            "methodical": "🔵 Methodical",
            "creative": "🟣 Creative",
        }

        for p in personas:
            table.add_row(
                p.name,
                style_names.get(p.style.value if hasattr(p.style, 'value') else str(p.style), str(p.style)),
                p.focus_domain,
            )

        con.print(table)
        con.print("\n[dim]The Council deliberates on complex issues, combining multiple personas' perspectives.[/dim]")
        con.print("[dim]Ask 'council' or mention 'council' in your message to trigger deliberation.[/dim]\n")
    except Exception as e:
        con.print(f"[red]Failed to load council info: {e}[/red]")


def _print_chat_history(history: list[dict]):
    """Print chat history."""
    if not history:
        con.print("[dim]No chat history yet.[/dim]")
        return

    con.print(f"\n[bold]📋 Chat History ({len(history)} messages)[/bold]\n")
    for msg in history[-20:]:
        role = "You" if msg["role"] == "user" else "Brain"
        content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
        con.print(f"  [bold]{role}:[/bold] {content}")
    con.print()


# ── Main entry point ───────────────────────────────────────────────────

def run(
    message: list[str] | str | None = None,
    json_output: bool = False,
    root: Path | None = None,
    stream: bool = False,
    explain_all: bool = False,
) -> None:
    """Entry point for `p chat` and `p ask` (backward compatible).

    Args:
        message: Single message or list of words.
        json_output: Output as JSON.
        root: Override project root.
        stream: Show real-time tool execution progress.
        explain_all: Show full security knowledge base.
    """
    try:
        from patchi.core.config import require_project_root
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg
    from patchi.core import memory as mem

    config = cfg.load(r)
    brain_state = mem.get_brain(r)

    # --explain-all: show full security knowledge base
    if explain_all:
        _show_explain_all()
        return

    # Single message mode
    if message:
        if isinstance(message, list):
            message = " ".join(message)
        if not message.strip():
            con.print("[red]Error: no message provided[/red]")
            return

        _process_message(message, r, config, brain_state, json_output=json_output, stream=stream)
        return

    # Interactive mode
    con.print()
    stream_label = " [green](streaming)[/green]" if stream else ""
    con.print(
        Panel(
            f"[bold]Patchi Chat — The Brain[/bold]{stream_label}\n"
            "[dim]Direct access to files, commands, agents, and intelligence.[/dim]\n"
            "[dim]Type 'quit' to exit, 'help' for commands, 'tools' to list available tools.[/dim]",
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
        if user_input.lower() == "help":
            _print_help()
            continue
        if user_input.lower() == "tools":
            _print_tools()
            continue
        if user_input.lower() == "council":
            _print_council_info(r)
            continue
        if user_input.lower() == "history":
            _print_chat_history(history)
            continue
        if user_input.lower().startswith("clear"):
            history.clear()
            _save_chat_history(r, history)
            con.print("[dim]Chat history cleared.[/dim]")
            continue

        # Process the message through the Brain
        response = _process_message(user_input, r, config, brain_state, history=history, stream=stream)
        if response:
            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": response})
            history[:] = history[-MAX_HISTORY:]
            _save_chat_history(r, history)
