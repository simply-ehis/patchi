"""
`p key` — Manage API keys for AI providers.

Subcommands:
  p key add              — interactive: pick provider, paste key, save
  p key list             — show all keys with status
  p key remove <name>    — remove a key by nickname
  p key test [name]      — fire a cheap test request against one or all keys

Keys are stored in .patchi/.env (gitignored).
Only the nickname + provider name are stored in config.json — never the raw key.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con
from patchi.core import config as cfg
from patchi.core.config import require_project_root

# ── Provider registry ──────────────────────────────────────────────────────────
# (name, base_url, model, test_prompt_path, key_env_prefix, docs_url)
PROVIDERS: list[dict] = [
    {
        "name": "Groq",
        "base": "https://api.groq.com/openai/v1",
        "model": "llama3-8b-8192",
        "format": "openai",
        "docs": "console.groq.com",
    },
    {
        "name": "OpenAI",
        "base": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "format": "openai",
        "docs": "platform.openai.com",
    },
    {
        "name": "Anthropic",
        "base": "https://api.anthropic.com/v1",
        "model": "claude-haiku-4-5-20251001",
        "format": "anthropic",
        "docs": "console.anthropic.com",
    },
    {
        "name": "Google",
        "base": "https://generativelanguage.googleapis.com/v1beta",
        "model": "gemini-1.5-flash",
        "format": "google",
        "docs": "aistudio.google.com",
    },
    {
        "name": "Mistral",
        "base": "https://api.mistral.ai/v1",
        "model": "mistral-small-latest",
        "format": "openai",
        "docs": "console.mistral.ai",
    },
    {
        "name": "Cohere",
        "base": "https://api.cohere.ai/v1",
        "model": "command-r",
        "format": "cohere",
        "docs": "dashboard.cohere.com",
    },
    {
        "name": "Together",
        "base": "https://api.together.xyz/v1",
        "model": "meta-llama/Llama-3-8b-chat-hf",
        "format": "openai",
        "docs": "api.together.xyz",
    },
    {
        "name": "Fireworks",
        "base": "https://api.fireworks.ai/inference/v1",
        "model": "accounts/fireworks/models/llama-v3-8b-instruct",
        "format": "openai",
        "docs": "fireworks.ai",
    },
    {
        "name": "Perplexity",
        "base": "https://api.perplexity.ai",
        "model": "llama-3.1-sonar-small-128k-online",
        "format": "openai",
        "docs": "www.perplexity.ai/settings",
    },
    {
        "name": "OpenRouter",
        "base": "https://openrouter.ai/api/v1",
        "model": "meta-llama/llama-3-8b-instruct:free",
        "format": "openai",
        "docs": "openrouter.ai",
    },
    {
        "name": "Custom",
        "base": "",
        "model": "",
        "format": "openai",
        "docs": "Enter your own provider details",
    },
]

PROVIDER_NAMES = [p["name"] for p in PROVIDERS]


_log = logging.getLogger("patchi.cli.key_cmd")


def _secure_key_input(prompt: str) -> str:
    """
    Securely read an API key from stdin, with support for pasting in PowerShell.
    
    Uses getpass on Unix-like systems, but on Windows/PowerShell falls back to
    a method that allows pasting (getpass blocks pasting in some PowerShell versions).
    """
    # Try getpass first (works on most Unix, blocks paste in some PowerShell)
    try:
        import getpass
        return getpass.getpass(prompt + " ")
    except Exception:
        pass
    
    # Fallback: use rich's Prompt but without password masking
    # This allows pasting in PowerShell - the key is stored securely in .env anyway
    from rich.prompt import Prompt
    return Prompt.ask(prompt)


def _provider_by_name(name: str) -> dict | None:
    for p in PROVIDERS:
        if p["name"].lower() == name.lower():
            return p
    return None


# ── Commands ───────────────────────────────────────────────────────────────────


def run_add(root: Path | None = None) -> None:
    """p key add — interactive key addition."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    con.print()
    con.print("[bold #F2EDD6]Add an API Key[/bold #F2EDD6]")
    con.print()

    # Show provider list
    for i, p in enumerate(PROVIDERS, 1):
        con.print(f"  [bold]{i:>2}.[/bold] {p['name']:<14} [dim]{p['docs']}[/dim]")
    con.print()

    # Provider pick
    raw = Prompt.ask("[#F2EDD6]Provider number or name[/#F2EDD6]")
    provider_data = None
    if raw.isdigit():
        idx = int(raw) - 1
        if 0 <= idx < len(PROVIDERS):
            provider_data = PROVIDERS[idx]
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
        base_url = Prompt.ask("[#F2EDD6]API base URL[/#F2EDD6]", default="")
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
        f"[#4ADE80]✓[/#4ADE80] Key [bold]{nickname}[/bold] saved.\n"
        f"[dim]Env var: {env_var} · File: .patchi/.env[/dim]"
    )
    con.print()

    # Offer to test immediately
    if Confirm.ask("Test this key now?", default=True):
        run_test(nickname, root=r)


def run_list(root: Path | None = None) -> None:
    """p key list"""
    try:
        r = root or require_project_root()
        config = cfg.load(r)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    keys: list[dict] = config.get("ai", {}).get("keys", [])
    local_model = config.get("ai", {}).get("local_model_name")

    con.print()

    if not keys and not local_model:
        con.print("[dim]No AI keys configured.[/dim]")
        con.print("[dim]Run [bold]p key add[/bold] to add one.[/dim]")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Nickname", style="bold #F2EDD6", width=16)
    table.add_column("Provider", style="#B8A898", width=12)
    table.add_column("Model", style="dim", width=30)
    table.add_column("Status", width=10)
    table.add_column("Env Var", style="dim", width=28)

    if local_model:
        table.add_row(
            "local",
            "Ollama",
            local_model,
            Text("local", style="#4ADE80"),
            "—",
        )

    for key in keys:
        status_val = key.get("status", "untested")
        status_colors = {
            "ok": "#4ADE80",
            "error": "red",
            "untested": "dim",
        }
        status_text = Text(status_val, style=status_colors.get(status_val, "dim"))

        table.add_row(
            key.get("nickname", "?"),
            key.get("provider", "?"),
            key.get("model", "?"),
            status_text,
            key.get("env_var", "?"),
        )

    con.print(table)
    con.print()
    con.print("[dim]Run [bold]p key test[/bold] to verify all keys.[/dim]")
    con.print()


def run_remove(nickname: str, root: Path | None = None) -> None:
    """p key remove <nickname>"""
    try:
        r = root or require_project_root()
        config = cfg.load(r)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    keys: list[dict] = config.get("ai", {}).get("keys", [])
    target = next((k for k in keys if k.get("nickname") == nickname), None)

    if not target:
        con.print(f"[yellow]No key with nickname {nickname!r} found.[/yellow]")
        return

    env_var = target.get("env_var", "")
    con.print(
        f"[yellow]Remove key [bold]{nickname}[/bold] ({target.get('provider', '?')})?[/yellow]"
    )
    if Confirm.ask("Confirm removal", default=False):
        keys = [k for k in keys if k.get("nickname") != nickname]
        cfg.set_value("ai.keys", keys, r)
        # Remove from .env file
        if env_var:
            _remove_env_var(r / ".patchi" / ".env", env_var)
        con.print(f"[#4ADE80]✓[/#4ADE80] Key [bold]{nickname}[/bold] removed.")
    else:
        con.print("[dim]Cancelled.[/dim]")


def run_test(nickname: str | None = None, root: Path | None = None) -> None:
    """p key test [nickname] — test one or all keys"""
    try:
        r = root or require_project_root()
        config = cfg.load(r)
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    # Load env from .patchi/.env
    _load_env_file(r / ".patchi" / ".env")

    keys: list[dict] = config.get("ai", {}).get("keys", [])
    if nickname:
        keys = [k for k in keys if k.get("nickname") == nickname]
        if not keys:
            con.print(f"[yellow]No key with nickname {nickname!r}.[/yellow]")
            return

    if not keys:
        con.print("[dim]No keys to test.[/dim]")
        return

    con.print()
    updated_keys: list[dict] = list(config.get("ai", {}).get("keys", []))

    for key in keys:
        nick = key.get("nickname", "?")
        provider = key.get("provider", "?")
        env_var = key.get("env_var", "")
        fmt = key.get("format", "openai")
        base_url = key.get("base_url", "")
        model = key.get("model", "")

        api_key = os.environ.get(env_var, "")
        if not api_key:
            con.print(
                f"  [yellow]⚠[/yellow] [bold]{nick}[/bold] — env var {env_var} not set or empty"
            )
            continue

        con.print(f"  Testing [bold]{nick}[/bold] ({provider})…", end=" ")

        try:
            result = _test_key(api_key, fmt, base_url, model)
            if result["ok"]:
                con.print(f"[#4ADE80]✓[/#4ADE80] [dim]{result['latency_ms']}ms[/dim]")
                _update_key_status(updated_keys, nick, "ok")
            else:
                con.print(f"[red]✗[/red] [dim]{result['error']}[/dim]")
                _update_key_status(updated_keys, nick, "error")
        except Exception as e:
            con.print(f"[red]✗[/red] [dim]{e}[/dim]")
            _update_key_status(updated_keys, nick, "error")

    cfg.set_value("ai.keys", updated_keys, r)
    con.print()


# ── Key test probe ─────────────────────────────────────────────────────────────


def _test_key(api_key: str, fmt: str, base_url: str, model: str) -> dict:
    """
    Fire a minimal test request. Returns {ok, latency_ms, error}.
    Uses urllib to avoid requiring httpx/requests.
    """
    import json
    import time
    import urllib.error
    import urllib.request

    start = time.monotonic()

    if fmt == "openai":
        url = f"{base_url}/chat/completions"
        payload = json.dumps(
            {
                "model": model,
                "messages": [{"role": "user", "content": "Say: ok"}],
                "max_tokens": 5,
            }
        ).encode()
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    elif fmt == "anthropic":
        url = f"{base_url}/messages"
        payload = json.dumps(
            {
                "model": model,
                "max_tokens": 5,
                "messages": [{"role": "user", "content": "Say: ok"}],
            }
        ).encode()
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

    elif fmt == "google":
        url = f"{base_url}/models/{model}:generateContent?key={api_key}"
        payload = json.dumps(
            {
                "contents": [{"parts": [{"text": "Say: ok"}]}],
                "generationConfig": {"maxOutputTokens": 5},
            }
        ).encode()
        headers = {"Content-Type": "application/json"}

    elif fmt == "cohere":
        url = f"{base_url}/generate"
        payload = json.dumps(
            {
                "model": model,
                "prompt": "Say: ok",
                "max_tokens": 5,
            }
        ).encode()
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    else:
        return {"ok": False, "latency_ms": 0, "error": f"Unknown format: {fmt}"}

    try:
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        latency_ms = int((time.monotonic() - start) * 1000)
        return {"ok": True, "latency_ms": latency_ms, "error": ""}

    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:200]
        return {"ok": False, "latency_ms": 0, "error": f"HTTP {e.code}: {body}"}
    except Exception as e:
        return {"ok": False, "latency_ms": 0, "error": str(e)}


# ── .env helpers ───────────────────────────────────────────────────────────────


def _write_env_var(env_file: Path, key: str, value: str) -> None:
    """Append or update a KEY=VALUE line in .env file."""
    env_file.parent.mkdir(parents=True, exist_ok=True)

    data = {}
    if env_file.exists():
        try:
            content = env_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip()
        except Exception as e:
            _log.warning("_write_env_var failed: %s", e)
            data = {}

    data[key] = value
    lines = [f"{k}={v}" for k, v in data.items()]
    env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _remove_env_var(env_file: Path, key: str) -> None:
    """Remove an entry from .env file."""
    if not env_file.exists():
        return

    data = {}
    try:
        content = env_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                data[k.strip()] = v.strip()
    except Exception as e:
        _log.warning("_remove_env_var failed: %s", e)
        return

    if key in data:
        del data[key]
        lines = [f"{k}={v}" for k, v in data.items()]
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_env_file(env_file: Path) -> None:
    """Load .env file into os.environ (only missing vars)."""
    if not env_file.exists():
        return

    try:
        content = env_file.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                if k.strip() and k.strip() not in os.environ:
                    os.environ[k.strip()] = v.strip()
    except Exception as e:
        _log.warning("_load_env_file failed: %s", e)


def _ensure_gitignore(root: Path) -> None:
    """Make sure .patchi/.env is in .gitignore."""
    gitignore = root / ".gitignore"
    entry = ".patchi/.env"
    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8")
        if entry not in content:
            with gitignore.open("a", encoding="utf-8") as f:
                f.write(f"\n# Patchi key storage\n{entry}\n")
    else:
        gitignore.write_text(f"# Patchi key storage\n{entry}\n", encoding="utf-8")


def _update_key_status(keys: list[dict], nickname: str, status: str) -> None:
    for k in keys:
        if k.get("nickname") == nickname:
            k["status"] = status
            break
