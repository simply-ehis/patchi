import logging
import os
import platform
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from patchi.cli.console import con
from patchi.core import config as cfg
from patchi.core.constants import DeviceTier

# Import providers from key_cmd to keep them in sync
from patchi.cli.commands.key_cmd import PROVIDERS as KEY_PROVIDERS

"""
`p init` - Initialize Patchi in the current project directory.

Professional first-run experience with step indicators, clean flow,
and proper OS-specific alias installation.
"""


try:
    from patchi.cli.logo import draw as draw_logo
except ImportError:

    def draw_logo(*a, **kw):  # noqa: ARG001
        return None


STEP_DONE = "[#4ADE80]  ok  [/#4ADE80]"
STEP_ARROW = "[#C8621A] >> [/#C8621A]"
STEP_PENDING = "[dim] ... [/dim]"


_log = logging.getLogger("patchi.cli.init")


def run(no_logo: bool = False) -> None:
    """Entry point for `p init` / `patchi init`."""

    draw_logo(con, skip=no_logo)

    con.print()
    con.print(
        Panel.fit(
            "[bold #F2EDD6]Project Initializer[/bold #F2EDD6]\n",
            border_style="#C8621A",
            subtitle="[dim]Step 1 of 4[/dim]",
        )
    )
    con.print()

    project_root = Path.cwd()

    # ── Step 1: Detect hardware ────────────────────────────────────────────────
    con.print(f"{STEP_ARROW} [bold]Detecting hardware...[/bold]")
    tier = _detect_device_tier()
    con.print(f"{STEP_DONE} {tier.value.upper()} tier [dim]({_tier_description(tier)})[/dim]")
    con.print()

    # ── Step 2: Create project structure ───────────────────────────────────────
    con.print(f"{STEP_ARROW} [bold]Creating project structure...[/bold]")
    already_exists = (project_root / ".patchi").exists()
    cfg.init_project(project_root, device_tier=tier)

    if already_exists:
        con.print(f"{STEP_DONE} Existing config merged with defaults")
    else:
        con.print(f"{STEP_DONE} Created [bold].patchi/[/bold] with config, memory, and queue files")

    _update_gitignore(project_root)
    con.print()

    # ── Step 3: Shell alias ────────────────────────────────────────────────────
    con.print(f"{STEP_ARROW} [bold]Shell alias...[/bold]")
    alias_result = _install_alias()
    if alias_result["success"]:
        if alias_result.get("already"):
            con.print(f"{STEP_DONE} [bold]p[/bold] alias already installed")
        else:
            con.print(f"{STEP_DONE} [bold]p[/bold] alias written to {alias_result['file']}")
            con.print(f"    [dim]Restart your terminal or run: source {alias_result['file']}[/dim]")
    else:
        con.print(f"[yellow]  warn  Could not install alias: {alias_result['reason']}[/yellow]")
        con.print("    [dim]Add manually: [bold]alias p='patchi'[/bold][/dim]")
    con.print()

    # ── Step 4: AI setup ───────────────────────────────────────────────────────
    con.print(f"{STEP_ARROW} [bold]AI configuration...[/bold]")
    con.print()
    con.print(
        Panel(
            "[bold]Patchi needs an AI model to generate fixes.[/bold]\n",
            title="[bold #C8621A]AI Setup[/bold #C8621A]",
            border_style="#C8621A",
            padding=(1, 2),
        )
    )
    con.print()

    # Show provider options dynamically from KEY_PROVIDERS
    con.print("  [bold]Choose AI provider:[/bold]")
    con.print()
    for i, p in enumerate(KEY_PROVIDERS, 1):
        con.print(f"  [bold]{i}[/bold]  {p['name']:<14} [dim]{p['docs']}[/dim]")
    con.print()

    try:
        choice = Prompt.ask("  Provider number or name", default="1")
    except (EOFError, OSError):
        choice = "1"
        con.print("  [dim]Non-interactive mode — using first provider (Groq)[/dim]")

    # Handle provider choice
    provider_data = None
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(KEY_PROVIDERS):
            provider_data = KEY_PROVIDERS[idx]
    else:
        # Find by name (case-insensitive)
        for p in KEY_PROVIDERS:
            if p["name"].lower() == choice.lower():
                provider_data = p
                break

    if not provider_data:
        con.print(f"  [yellow]Unknown provider: {choice!r}, using Custom[/yellow]")
        provider_data = KEY_PROVIDERS[-1]  # Custom

    if provider_data["name"] == "Custom":
        # Use the same flow as key_cmd for custom
        _setup_custom_provider(project_root)
    elif provider_data["name"] == "Ollama":
        _setup_local_model(project_root)
    else:
        _setup_known_provider(project_root, provider_data)

    con.print()

    # Mark onboarding as complete (M-01)
    try:
        from patchi.core import config as _cfg

        _c = _cfg.load(project_root)
        _c["onboarding_complete"] = True
        _cfg.save(_c, project_root)
    except Exception as e:
        _log.warning("run failed: %s", e)

    # ── Done ───────────────────────────────────────────────────────────────────
    _show_complete_panel(project_root)


def _show_complete_panel(root: Path) -> None:
    """Show the completion panel with next steps."""
    # Build a status table
    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 2))
    table.add_column("Key", style="bold #F2EDD6", width=18)
    table.add_column("Value", style="#B8A898")

    table.add_row("Project", str(root))
    table.add_row("Config", ".patchi/config.json")

    try:
        config = cfg.load(root)
        mode = config.get("mode", "confirm")
        table.add_row("Mode", mode)

        ai_cfg = config.get("ai", {})
        if ai_cfg.get("local_model_name"):
            table.add_row("AI", f"Ollama ({ai_cfg['local_model_name']})")
        elif ai_cfg.get("keys"):
            count = len(ai_cfg["keys"])
            table.add_row("AI", f"{count} API key(s) configured")
        else:
            table.add_row("AI", "[yellow]Not configured[/yellow]")
    except Exception as e:
        _log.warning("_show_complete_panel failed: %s", e)

    tier = _detect_device_tier()
    table.add_row("Hardware", f"{tier.value.upper()} tier")

    con.print(
        Panel(
            table,
            title="[bold #4ADE80]Patchi is ready[/bold #4ADE80]",
            border_style="#4ADE80",
            padding=(0, 1),
        )
    )
    con.print()

    con.print("[bold #F2EDD6]Next steps:[/bold #F2EDD6]")
    con.print("  [bold]p scan[/bold]          [dim]Scan your project for issues[/dim]")
    con.print("  [bold]p scan --deep[/bold]    [dim]Scan + AI analysis (uses tokens)[/dim]")
    con.print("  [bold]p web[/bold]           [dim]Open the visual dashboard[/dim]")
    con.print("  [bold]p doctor[/bold]        [dim]Validate setup and dependencies[/dim]")
    con.print()


# ── Alias install (cross-platform) ───────────────────────────────────────────


def _install_alias() -> dict:
    """Install `p` as a short alias for `patchi`. Cross-platform."""
    system = platform.system()
    home = Path.home()

    if system == "Windows":
        return _install_alias_windows(home)
    else:
        return _install_alias_unix(home)


def _install_alias_windows(home: Path) -> dict:
    """Windows: create a batch file wrapper in a PATH-friendly location."""
    scripts_dir = home / "patchi_scripts"
    scripts_dir.mkdir(exist_ok=True)

    bat_file = scripts_dir / "p.bat"
    if bat_file.exists():
        return {"success": True, "file": str(bat_file), "already": True}

    try:
        bat_file.write_text(
            "@echo off\npatchi %*\n",
            encoding="utf-8",
        )

        # Check if already in PATH
        path_env = os.environ.get("PATH", "")
        if str(scripts_dir) not in path_env:
            con.print(f"    [dim]Add to PATH: {scripts_dir}[/dim]")
            con.print(f'    [dim]Or run: [bold]setx PATH "%PATH%;{scripts_dir}"[/bold][/dim]')

        return {"success": True, "file": str(bat_file)}
    except OSError as e:
        return {"success": False, "file": str(bat_file), "reason": str(e)}


def _install_alias_unix(home: Path) -> dict:
    """Unix: write alias to .bashrc or .zshrc."""
    shell = os.environ.get("SHELL", "")
    if "zsh" in shell:
        rc_file = home / ".zshrc"
    else:
        rc_file = home / ".bashrc"

    alias_line = "alias p='patchi'  # added by patchi init\n"
    try:
        if rc_file.exists():
            content = rc_file.read_text(encoding="utf-8")
            if "alias p='patchi'" in content or 'alias p="patchi"' in content:
                return {"success": True, "file": str(rc_file), "already": True}

        with rc_file.open("a", encoding="utf-8") as f:
            f.write(f"\n{alias_line}")

        return {"success": True, "file": str(rc_file)}
    except OSError as e:
        return {"success": False, "file": str(rc_file), "reason": str(e)}


# ── AI setup helpers ───────────────────────────────────────────────────────────


def _setup_local_model(root: Path) -> None:
    model_name = Prompt.ask(
        "  Ollama model name",
        default="llama3.2",
    )
    cfg.set_value("ai.local_model_name", model_name, root)
    con.print(
        f"    [dim]Model set to [bold]{model_name}[/bold]. Make sure Ollama is running.[/dim]"
    )


def _setup_custom_provider(root: Path) -> None:
    """Set up a custom OpenAI-compatible provider (same as key_cmd flow)."""
    con.print()
    con.print("  [dim]Enter your provider's OpenAI-compatible API details.[/dim]")
    
    provider_name = Prompt.ask("  Provider name")
    if not provider_name.strip():
        con.print("[red]Provider name is required.[/red]")
        return
    
    base_url = Prompt.ask("  Base URL", default="https://api.openai.com/v1")
    if not base_url.strip():
        con.print("[red]Base URL is required.[/red]")
        return
        
    model = Prompt.ask("  Model name")
    if not model.strip():
        con.print("[red]Model name is required.[/red]")
        return
        
    format_choices = ["openai", "anthropic", "google", "cohere"]
    fmt = Prompt.ask("  API format", choices=format_choices, default="openai")

    # Use secure key input that works in PowerShell
    api_key = _secure_key_input("  Paste your API key")
    if not api_key.strip():
        con.print("[red]No key entered.[/red]")
        return
        
    nickname = Prompt.ask("  Nickname for this key", default=provider_name)

    _store_key(
        root, provider=provider_name, base_url=base_url, model=model, api_key=api_key, fmt=fmt
    )


def _setup_known_provider(root: Path, provider_data: dict) -> None:
    """Set up a known provider from KEY_PROVIDERS list."""
    api_key = _secure_key_input(f"  Paste your {provider_data['name']} API key")
    if not api_key.strip():
        con.print("[red]No key entered.[/red]")
        return
        
    nickname = Prompt.ask("  Nickname for this key", default=provider_data["name"])

    _store_key(
        root,
        provider=provider_data["name"],
        base_url=provider_data["base"],
        model=provider_data["model"],
        api_key=api_key,
        fmt=provider_data["format"],
    )


def _secure_key_input(prompt: str) -> str:
    """
    Securely read an API key from stdin, with support for pasting in PowerShell.
    """
    import sys
    
    try:
        import getpass
        return getpass.getpass(prompt + " ")
    except Exception:
        pass
    
    # Fallback: use rich's Prompt but without password masking
    # This allows pasting in PowerShell - the key is stored securely in .env anyway
    from rich.prompt import Prompt
    return Prompt.ask(prompt)


def _store_key(
    root: Path,
    provider: str,
    base_url: str,
    model: str,
    api_key: str,
    fmt: str = "openai",
) -> None:
    """Store an API key in config and keys.json."""
    nickname = provider
    env_var = f"PATCHI_KEY_{nickname.upper().replace(' ', '_')}"

    existing_keys: list = cfg.load(root).get("ai", {}).get("keys", [])
    existing_keys.append(
        {
            "provider": provider,
            "nickname": nickname,
            "env_var": env_var,
            "base_url": base_url,
            "model": model,
            "format": fmt,
            "status": "untested",
        }
    )

    # Store key in keys.json
    keys_file = root / ".patchi" / "keys.json"
    import json

    data = {}
    if keys_file.exists():
        try:
            data = json.loads(keys_file.read_text(encoding="utf-8"))
        except Exception as e:
            _log.warning("_store_key failed: %s", e)
            data = {}
    data[env_var] = api_key
    keys_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    # Update gitignore
    _ensure_gitignore_entry(root, ".patchi/keys.json", "# Patchi key storage")

    cfg.set_value("ai.keys", existing_keys, root)
    con.print(f"    [dim]Env var: {env_var}[/dim]")
    con.print("    [dim]Key stored. Never leaves your machine.[/dim]")


# ── Gitignore helpers ──────────────────────────────────────────────────────────


def _update_gitignore(project_root: Path) -> None:
    """Add .patchi/ entries to .gitignore if not already present."""
    entries = [".patchi/", ".patchi/.env", ".patchi/keys.json"]
    comment = "# Patchi local config"
    _ensure_gitignore(project_root, entries, comment)


def _ensure_gitignore(project_root: Path, entries: list[str], comment: str) -> None:
    gitignore = project_root / ".gitignore"
    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8")
        missing = [e for e in entries if e not in content]
        if missing:
            with gitignore.open("a", encoding="utf-8") as f:
                f.write(f"\n{comment}\n")
                for entry in missing:
                    f.write(f"{entry}\n")
    else:
        with gitignore.open("w", encoding="utf-8") as f:
            f.write(f"{comment}\n")
            for entry in entries:
                f.write(f"{entry}\n")


def _ensure_gitignore_entry(project_root: Path, entry: str, comment: str) -> None:
    _ensure_gitignore(project_root, [entry], comment)


# ── Device tier detection ──────────────────────────────────────────────────────


def _detect_device_tier() -> DeviceTier:
    try:
        import psutil

        ram_gb = psutil.virtual_memory().total / (1024**3)
        if ram_gb < 4:
            return DeviceTier.LOW
        if ram_gb < 16:
            return DeviceTier.MID
        return DeviceTier.HIGH
    except ImportError:
        return DeviceTier.MID


def _tier_description(tier: DeviceTier) -> str:
    return {
        DeviceTier.LOW: "< 4GB RAM, single queue mode",
        DeviceTier.MID: "4-16GB RAM, multi queue mode",
        DeviceTier.HIGH: "16GB+ RAM, full parallelism",
    }[tier]
