"""
`p ai` — AI configuration and status.

Subcommands:
  p ai status          — Show all configured AI keys and their status
  p ai test            — Send a test prompt to the active AI provider
  p ai add             — Add a new API key interactively
  p ai remove <name>   — Remove an API key by name
  p ai profiles        — List configured AI provider profiles
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from rich.table import Table
from rich.text import Text

from patchi.cli.commands.key_cmd import PROVIDERS as KEY_PROVIDERS
from patchi.cli.commands.key_cmd import _ensure_gitignore, _secure_key_input, _write_env_var
from patchi.cli.console import con
from patchi.core.config import require_project_root

_TEST_PROMPT = "Reply with exactly: PATCHI AI READY"


def _provider_by_name(name: str) -> dict | None:
    for p in KEY_PROVIDERS:
        if p["name"].lower() == name.lower():
            return p
    return None


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
        "[dim]Profile schema (E-12 S-2): nickname, provider, env_var, base_url, model, format, status, extra_body[/dim]"
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
            status = Text("ready", style="#4ADE80") if has_key else Text("missing env", style="#FACC15")
            table.add_row(
                k.get("nickname", "?"),
                k.get("base_url", "").replace("https://", "").split("/")[0][:16],
                k.get("model", "?"),
                status,
            )
        con.print(table)
    else:
        con.print("  [dim]No API keys configured. Run: p ai add[/dim]")

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
        con.print("  [dim]No AI configured or all keys failed.[/dim]")
    con.print()


def run_add(root: Path | None = None) -> None:
    from rich.prompt import Prompt

    import patchi.core.config as cfg

    r = _resolve_root(root)

    con.print()
    con.print("[bold #C8621A]Add AI Key[/bold #C8621A]")
    con.print()

    # Show provider list (same as key add)
    for i, p in enumerate(KEY_PROVIDERS, 1):
        con.print(f"  [bold]{i:>2}.[/bold] {p['name']:<14} [dim]{p['docs']}[/dim]")
    con.print()

    # Provider pick
    raw = Prompt.ask("[#F2EDD6]Provider number or name[/#F2EDD6]")
    provider_data = None
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(KEY_PROVIDERS):
            provider_data = KEY_PROVIDERS[idx]
    else:
        provider_data = _provider_by_name(raw)

    if not provider_data:
        con.print(f"[red]Unknown provider: {raw!r}[/red]")
        return

    provider_name = provider_data["name"]

    # Handle Custom provider - prompt for details
    if provider_name == "Custom":
        provider_name = Prompt.ask("[#F2EDD6]Provider name[/#F2EDD6]")
        if not provider_name.strip():
            con.print("[red]Provider name is required.[/red]")
            return
        base_url = Prompt.ask("[#F2EDD6]API base URL[/#F2EDD6]", default="https://api.openai.com/v1")
        if not base_url.strip():
            con.print("[red]Base URL is required.[/red]")
            return
        model = Prompt.ask("[#F2EDD6]Model name[/#F2EDD6]")
        if not model.strip():
            con.print("[red]Model name is required.[/red]")
            return
        format_choices = ["openai", "anthropic", "google", "cohere"]
        fmt = Prompt.ask("[#F2EDD6]API format[/#F2EDD6]", choices=format_choices, default="openai")
        provider_data = {
            "name": provider_name,
            "base": base_url.strip(),
            "model": model.strip(),
            "format": fmt,
            "docs": "custom",
        }

    # Nickname
    nickname = Prompt.ask(
        "[#F2EDD6]Nickname for this key[/#F2EDD6]",
        default=provider_name,
    )

    # Key input - use secure input that works in PowerShell
    key_value = _secure_key_input("[#F2EDD6]Paste your API key[/#F2EDD6]")
    if not key_value.strip():
        con.print("[red]No key entered.[/red]")
        return

    # Build env var name
    env_var = f"PATCHI_KEY_{nickname.upper().replace(' ', '_').replace('-', '_')}"

    # Write to .patchi/.env
    env_file = r / ".patchi" / ".env"
    _write_env_var(env_file, env_var, key_value.strip())

    # Add to .gitignore
    _ensure_gitignore(r)

    # Save to config
    config = cfg.load(r)
    keys: list[dict] = config.get("ai", {}).get("keys", [])

    # Replace if nickname already exists
    keys = [k for k in keys if k.get("nickname") != nickname]
    keys.append(
        {
            "provider": provider_name,
            "nickname": nickname,
            "env_var": env_var,
            "format": provider_data["format"],
            "base_url": provider_data["base"],
            "model": provider_data["model"],
            "status": "untested",
        }
    )
    cfg.set_value("ai.keys", keys, r)

    con.print()
    con.print(
        f"[#4ADE80]✓[/#4ADE80] Key [bold]{nickname}[/bold] saved.\n[dim]Env var: {env_var} · File: .patchi/.env[/dim]"
    )
    con.print()

    # Offer to test immediately
    from rich.prompt import Confirm

    if Confirm.ask("Test this key now?", default=True):
        run_test(nickname, root=r)


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
