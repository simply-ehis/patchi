"""
`p notify` — manage notification channels.
list | add <type> | remove <name> | test [name] | ack <id> | flush | pending
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

import patchi.core.config as config
from patchi.cli.commands.notify_prompts import CHANNEL_SETUP_FIELDS, SEVERITY_CHOICES
from patchi.core.notifications.channels import ChannelType, from_config
from patchi.core.notifications.notifier import Notifier

console = Console()


def run_notify(args) -> None:
    sub = getattr(args, "notify_cmd", None)

    if sub == "list" or sub is None:
        _cmd_list(args)
    elif sub == "add":
        _cmd_add(args)
    elif sub == "remove":
        _cmd_remove(args)
    elif sub == "test":
        _cmd_test(args)
    elif sub == "ack":
        _cmd_ack(args)
    elif sub == "flush":
        _cmd_flush(args)
    elif sub == "pending":
        _cmd_pending(args)


def _cmd_list(args) -> None:
    root = _require_root()
    cfg = config.load(root)
    channels = cfg.get("notifications", [])

    if not channels:
        console.print("[dim]No notification channels configured.[/dim]")
        console.print("Add one with: [bold]p notify add slack[/bold]")
        return

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Type", style="white")
    table.add_column("Min Severity", style="yellow")
    table.add_column("Digest", style="dim")

    for ch in channels:
        table.add_row(
            ch.get("name", "—"),
            ch.get("type", "—"),
            ch.get("min_severity", "medium"),
            "yes" if ch.get("in_digest") else "no",
        )

    console.print(table)
    quiet = cfg.get("quiet_hours", {})
    if quiet.get("enabled"):
        console.print(f"\n[dim]Quiet hours: {quiet['start']} → {quiet['end']} ({quiet.get('timezone', 'UTC')})[/dim]")
    console.print(f"[dim]Digest frequency: {cfg.get('digest_frequency', 'daily')}[/dim]")


def _prompt_credentials(channel_type: str) -> dict[str, str]:
    """Prompt for channel-specific credentials. Returns a dict of field→value."""
    credentials: dict[str, str] = {}
    for field_key, prompt in CHANNEL_SETUP_FIELDS.get(channel_type, []):
        value = console.input(f"[cyan]{prompt}: [/cyan]").strip()
        if value:
            credentials[field_key] = value
    return credentials


def _cmd_add(args) -> None:
    root = _require_root()
    channel_type = getattr(args, "channel_type", None)

    valid_types = [t.value for t in ChannelType]
    if not channel_type or channel_type not in valid_types:
        console.print(f"[red]Specify a channel type:[/red] {', '.join(valid_types)}")
        return

    console.print(f"\n[bold]Adding {channel_type} channel[/bold]")
    name = console.input("[cyan]Channel name (e.g. my-slack): [/cyan]").strip()
    if not name:
        console.print("[red]Name cannot be empty.[/red]")
        return

    credentials: dict[str, str] = _prompt_credentials(channel_type)

    min_severity = (
        console.input(f"[cyan]Minimum severity [{'/'.join(SEVERITY_CHOICES)}] (default: medium): [/cyan]").strip()
        or "medium"
    )
    if min_severity not in SEVERITY_CHOICES:
        min_severity = "medium"

    in_digest_raw = console.input("[cyan]Batch into digest? (y/n, default: n): [/cyan]").strip().lower()
    in_digest = in_digest_raw == "y"

    raw = {
        "name": name,
        "type": channel_type,
        "min_severity": min_severity,
        "in_digest": in_digest,
        **credentials,
    }

    # Validate before saving
    try:
        from_config(raw)
    except ValueError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        return

    cfg = config.load(root)
    cfg.setdefault("notifications", [])

    if any(ch["name"] == name for ch in cfg["notifications"]):
        console.print(f"[red]A channel named '{name}' already exists.[/red]")
        return

    cfg["notifications"].append(raw)
    config.save(cfg, root)
    console.print(f"[green]✓ Channel '{name}' added.[/green]")
    console.print("Run [bold]p notify test[/bold] to verify it works.")


def _cmd_remove(args) -> None:
    root = _require_root()
    name = getattr(args, "channel_name", None)
    if not name:
        console.print("[red]Specify a channel name to remove.[/red]")
        return

    cfg = config.load(root)
    before = len(cfg.get("notifications", []))
    cfg["notifications"] = [ch for ch in cfg.get("notifications", []) if ch.get("name") != name]

    if len(cfg["notifications"]) == before:
        console.print(f"[red]No channel named '{name}' found.[/red]")
        return

    config.save(cfg, root)
    console.print(f"[green]✓ Channel '{name}' removed.[/green]")


def _cmd_test(args) -> None:
    root = _require_root()
    target = getattr(args, "channel_name", None)
    if not config.load(root).get("notifications"):
        console.print("[dim]No channels configured. Add one with p notify add.[/dim]")
        return
    for ch_name, ok in _notifier(root).test(target):
        console.print(f"  {ch_name}: {'[green]✓ sent[/green]' if ok else '[red]✗ failed[/red]'}")


def _cmd_ack(args) -> None:
    aid = getattr(args, "alert_id", None)
    if not aid:
        console.print("[red]Provide an alert ID to acknowledge.[/red]")
        return
    ok = _notifier(_require_root()).acknowledge(aid)
    msg = f"[green]✓ Alert {aid} acknowledged.[/green]" if ok else f"[red]Alert ID '{aid}' not found.[/red]"
    console.print(msg)


def _cmd_flush(args) -> None:
    sent = _notifier(_require_root()).flush_digest()
    console.print(f"[green]✓ Digest flushed to {sent} channel(s).[/green]" if sent else "[dim]Nothing to flush.[/dim]")


def _cmd_pending(args) -> None:
    pending = _notifier(_require_root()).pending_escalations()
    if not pending:
        console.print("[dim]No pending escalations.[/dim]")
        return
    for alert in pending:
        console.print(f"  [red]{alert['id']}[/red]  {alert['severity'].upper()}  {alert['title']}")
    console.print("\nAck with: [bold]p notify ack <id>[/bold]")


def _notifier(root: Path) -> Notifier:
    return Notifier(root, config.load(root))


def _require_root() -> Path:
    try:
        return config.require_project_root()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1) from exc
