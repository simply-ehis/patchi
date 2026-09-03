"""
`p ai` — AI configuration and status.

Subcommands:
  p ai status          — Show all configured AI keys and their status
  p ai test            — Send a test prompt to the active AI provider
  p ai horde           — Test the AI Horde community endpoint (key 0000000000)
  p ai add             — Add a new API key interactively
  p ai remove <name>   — Remove an API key by name
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core.config import require_project_root

_TEST_PROMPT = "Reply with exactly: PATCHI AI READY"


def run(args) -> None:
    ai_cmd = getattr(args, "ai_cmd", None) or "status"
    try:
        root = require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    if ai_cmd == "status":
        run_status(root)
    elif ai_cmd == "test":
        run_test(root)
    elif ai_cmd == "horde":
        run_horde_test()
    elif ai_cmd == "add":
        run_add(root)
    elif ai_cmd == "remove":
        run_remove(root, getattr(args, "name", ""))
    else:
        con.print(f"[red]Unknown ai subcommand: {ai_cmd!r}[/red]")


def run_profiles(root=None) -> None:
    """List configured AI provider profiles (E-12 S-2 seed: p ai profiles)."""
    from rich.table import Table

    from patchi.cli.console import con

    r = _resolve_root(root)
    from patchi.core import config as cfg

    keys = cfg.load(r).get("ai", {}).get("keys", [])
    con.print()
    if not keys:
        con.print("[yellow]No AI provider profiles configured.[/yellow]")
        con.print("[dim]Add one with `p key add` or edit .patchi/config.json.[/dim]")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Nickname", style="bold #F2EDD6", width=14)
    table.add_column("Provider", width=10)
    table.add_column("Model", width=28)
    table.add_column("Base URL", width=40)
    table.add_column("Status", width=7)
    table.add_column("Env Var", style="dim")

    for k in keys:
        status = k.get("status", "?")
        color = {"ok": "#4ADE80", "error": "#FF4D6D"}.get(status, "#FACC15")
        table.add_row(
            k.get("nickname", "?"),
            k.get("provider", "?"),
            k.get("model", "?"),
            k.get("base_url", "?"),
            f"[{color}]{status}[/{color}]",
            k.get("env_var", "?"),
        )
    con.print(table)
    con.print()
    con.print(
        "[dim]Profile schema (E-12 S-2): nickname, provider, env_var, "
        "base_url, model, format, status, extra_body[/dim]"
    )
    con.print()


def _resolve_root(root: Path | None) -> Path:
    if root is not None:
        return root
    try:
        return require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        raise SystemExit(1) from e


def run_status(root: Path | None = None) -> None:
    import patchi.core.config as cfg

    config = cfg.load(_resolve_root(root))
    ai_cfg = config.get("ai", {})
    keys = ai_cfg.get("keys", [])
    horde = ai_cfg.get("horde_fallback", False)
    horde_key = ai_cfg.get("horde_key", "0000000000")
    local = ai_cfg.get("local_model_name")

    con.print()
    con.print("[bold #C8621A]AI Configuration[/bold #C8621A]")
    con.print()

    # Local
    if local:
        con.print(f"  [#4ADE80]●[/#4ADE80] Local model (Ollama): [bold]{local}[/bold]")
    else:
        con.print("  [dim]○ Local model: not configured[/dim]")

    # API keys
    if keys:
        table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
        table.add_column("Name", style="bold", width=18)
        table.add_column("Provider", width=16)
        table.add_column("Model", width=24)
        table.add_column("Status", width=12)

        for k in keys:
            env_var = k.get("env_var", "")
            has_key = bool(os.environ.get(env_var))
            status = (
                Text("ready", style="#4ADE80") if has_key else Text("missing env", style="#FACC15")
            )
            table.add_row(
                k.get("nickname", "?"),
                k.get("base_url", "").replace("https://", "").split("/")[0][:16],
                k.get("model", "?"),
                status,
            )
        con.print(table)
    else:
        con.print("  [dim]No API keys configured. Run: p ai add[/dim]")

    # Horde
    horde_text = (
        f"[#4ADE80]enabled[/#4ADE80] (key: {horde_key})" if horde else "[dim]disabled[/dim]"
    )
    con.print()
    con.print(f"  AI Horde fallback: {horde_text}")
    con.print()


def run_test(root: Path | None = None) -> None:
    import patchi.core.config as cfg

    config = cfg.load(_resolve_root(root))

    con.print()
    con.print("[bold #C8621A]Testing AI Connection[/bold #C8621A]")
    con.print()

    from patchi.core.fix.base import _call_ai

    con.print("  Sending test prompt…", end=" ")
    t0 = time.monotonic()
    result = _call_ai(_TEST_PROMPT, config, max_tokens=20)
    elapsed = (time.monotonic() - t0) * 1000

    if result:
        con.print(f"[#4ADE80]OK[/#4ADE80] ({elapsed:.0f}ms)")
        con.print(f"  Response: [dim]{result[:120]}[/dim]")
    else:
        con.print("[#FACC15]No response[/#FACC15]")
        con.print("  [dim]No AI configured or all keys failed. Try: p ai horde[/dim]")
    con.print()


def run_horde_test() -> None:
    from patchi.core.ai.client import _call_ai_horde

    con.print()
    con.print("[bold #C8621A]Testing AI Horde (community key)[/bold #C8621A]")
    con.print("  [dim]This may take 10–60 seconds depending on worker availability…[/dim]")
    con.print()

    t0 = time.monotonic()
    result = _call_ai_horde("0000000000", _TEST_PROMPT, 30)
    elapsed = (time.monotonic() - t0) * 1000

    if result:
        con.print(f"  [#4ADE80]✓ AI Horde is working[/#4ADE80] ({elapsed:.0f}ms)")
        con.print(f"  Response: [dim]{result[:120]}[/dim]")
    else:
        con.print("  [#FACC15]⚠ AI Horde did not respond in time.[/#FACC15]")
        con.print("  [dim]Try again — Horde workers may be busy.[/dim]")
    con.print()


def run_add(root: Path | None = None) -> None:
    from rich.prompt import Prompt

    import patchi.core.config as cfg

    r = _resolve_root(root)

    con.print()
    con.print("[bold #C8621A]Add AI Key[/bold #C8621A]")
    con.print()

    nickname = Prompt.ask("  Nickname (e.g. openrouter-main)")
    base_url = Prompt.ask("  API base URL", default="https://openrouter.ai/api/v1")
    model = Prompt.ask("  Model", default="mistralai/mistral-7b-instruct")
    fmt = Prompt.ask("  Format", choices=["openai", "anthropic"], default="openai")
    env_name = Prompt.ask(
        "  Env var name (stores the key)", default=f"PATCHI_KEY_{nickname.upper()}"
    )

    config = cfg.load(r)
    ai_cfg = config.setdefault("ai", {})
    keys = ai_cfg.setdefault("keys", [])
    keys.append(
        {
            "nickname": nickname,
            "base_url": base_url,
            "model": model,
            "format": fmt,
            "env_var": env_name,
            "status": "ok",
        }
    )
    cfg.save(config, r)

    con.print()
    con.print("[#4ADE80]✓[/#4ADE80] Key added. Set the env var:")
    con.print(f"  [bold]export {env_name}=your_api_key_here[/bold]")
    con.print()


def run_remove(root: Path | None = None, name: str = "") -> None:
    import patchi.core.config as cfg

    if not name:
        con.print("[red]Usage: p ai remove <nickname>[/red]")
        return

    r = _resolve_root(root)
    config = cfg.load(r)
    keys = config.get("ai", {}).get("keys", [])
    before = len(keys)
    config["ai"]["keys"] = [k for k in keys if k.get("nickname") != name]

    if len(config["ai"]["keys"]) == before:
        con.print(f"[yellow]No key with nickname {name!r} found.[/yellow]")
        return

    cfg.save(config, r)
    con.print(f"[#4ADE80]✓[/#4ADE80] Key [bold]{name}[/bold] removed.")
