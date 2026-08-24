"""
`p hosted` — Hosted mode: monitor live applications in production.

Subcommands:
  p hosted init               — Interactive setup (log path, worker config)
  p hosted worker             — Start the background log-watching worker
  p hosted guard              — Start live guard with anomaly detection + watchlist
  p hosted status             — Show watchlist top threats and audit log summary
  p hosted logs               — Stream the audit log in real time
  p hosted token add          — Generate a new admin token (shown once)
  p hosted token list         — List all active tokens
  p hosted token revoke <id>  — Revoke a token by ID
  p hosted disconnect         — Clear hosted mode config

The hosted worker watches a log file (nginx/apache/uvicorn/gunicorn/caddy/cloudflare)
and runs statistical + ML anomaly detection on every new line.
Escalation fires through the notification system when thresholds are crossed.
"""

from __future__ import annotations
from patchi.cli.console import con

import os
import platform
import time
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from patchi.core.config import require_project_root

# ── Dispatch ───────────────────────────────────────────────────────────────────

import logging
_log = logging.getLogger("patchi.cli.hosted_cmd")

def run(args) -> None:
    """Main entry from CLI router — dispatches to sub-handlers."""
    hosted_cmd = getattr(args, "hosted_cmd", None)
    token_cmd = getattr(args, "token_cmd", None)

    if not hosted_cmd or hosted_cmd == "status":
        run_status(json_output=getattr(args, "json", False))
    elif hosted_cmd == "init":
        run_init()
    elif hosted_cmd == "worker":
        run_worker()
    elif hosted_cmd == "daemon":
        run_daemon(guard=getattr(args, "guard", False))
    elif hosted_cmd == "stop":
        run_stop()
    elif hosted_cmd == "guard":
        run_guard()
    elif hosted_cmd == "logs":
        run_logs()
    elif hosted_cmd == "disconnect":
        run_disconnect()
    elif hosted_cmd == "block":
        run_block(getattr(args, "ip", ""))
    elif hosted_cmd == "unblock":
        run_unblock(getattr(args, "ip", ""))
    elif hosted_cmd == "token":
        if not token_cmd or token_cmd == "list":
            run_token_list()
        elif token_cmd == "add":
            run_token_add()
        elif token_cmd == "revoke":
            run_token_revoke(getattr(args, "id", ""))
        else:
            con.print(f"[red]Unknown token subcommand: {token_cmd!r}[/red]")
    else:
        con.print(f"[red]Unknown hosted subcommand: {hosted_cmd!r}[/red]")

# ── init ───────────────────────────────────────────────────────────────────────

def run_init(root: Path | None = None) -> None:
    """Interactive hosted mode setup."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    con.print()
    con.print("[bold #C8621A]Hosted Mode Setup[/bold #C8621A]")
    con.print("[dim]Connects Patchi to a live application's log stream.[/dim]")
    con.print()

    from patchi.core import config as cfg

    # Log path
    log_path = Prompt.ask(
        "  Log file path",
        default="/var/log/nginx/access.log",
    )

    # Log format
    log_format = Prompt.ask(
        "  Log format",
        choices=["nginx", "apache", "caddy", "uvicorn", "gunicorn", "cloudflare", "json"],
        default="nginx",
    )

    # Notification on escalation
    escalate = Confirm.ask("  Enable notifications on threat escalation?", default=True)

    # Save to config
    cfg.set_value("hosted.log_path", log_path, r)
    cfg.set_value("hosted.log_format", log_format, r)
    cfg.set_value("hosted.escalate", escalate, r)
    cfg.set_value("hosted.enabled", True, r)

    # Create hosted dir
    hosted_dir = r / ".patchi" / "hosted"
    hosted_dir.mkdir(parents=True, exist_ok=True)

    con.print()
    con.print("[#4ADE80]✓[/#4ADE80] Hosted mode configured.")
    con.print(f"  [dim]Log:    {log_path}[/dim]")
    con.print(f"  [dim]Format: {log_format}[/dim]")
    con.print()
    con.print("  Start monitoring: [bold]p hosted worker[/bold]")
    con.print("  Live guard mode:  [bold]p hosted guard[/bold]")
    con.print()

# ── worker ─────────────────────────────────────────────────────────────────────

def run_worker(root: Path | None = None) -> None:
    """Start the background log-watching worker."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg

    config = cfg.load(r)
    log_path = config.get("hosted", {}).get("log_path", "")

    if not log_path:
        con.print("[red]Hosted mode not configured. Run: p hosted init[/red]")
        return

    log_file = Path(log_path)
    if not log_file.exists():
        con.print(f"[#FACC15]⚠  Log file not found: {log_path}[/#FACC15]")
        con.print("[dim]The worker will wait for it to appear.[/dim]")

    con.print()
    con.print(f"[bold #C8621A]Hosted Worker[/bold #C8621A]  [dim]tailing {log_path}[/dim]")
    con.print("[dim]Press Ctrl+C to stop.[/dim]")
    con.print()

    from patchi.core.hosted.audit_log import write as audit_write
    from patchi.core.hosted.log_parsers import parse_line

    lines_parsed = 0
    lines_failed = 0
    last_report = time.monotonic()

    try:
        with _tail_file(log_file) as lines:
            for raw_line in lines:
                entry = parse_line(raw_line)
                if entry:
                    lines_parsed += 1
                    audit_write(
                        r,
                        "log_line",
                        data={
                            "method": entry.method,
                            "path": entry.path,
                            "status": entry.status,
                            "ip": entry.ip,
                            "source": entry.source,
                        },
                    )
                else:
                    lines_failed += 1

                # Progress every 5s
                now = time.monotonic()
                if now - last_report >= 5:
                    con.print(
                        f"  [dim]parsed {lines_parsed} lines  |  unrecognised {lines_failed}[/dim]"
                    )
                    last_report = now

    except KeyboardInterrupt:
        con.print()
        con.print(f"[dim]Worker stopped. {lines_parsed} lines processed.[/dim]")
        con.print()

# ── guard ──────────────────────────────────────────────────────────────────────

def run_guard(root: Path | None = None) -> None:
    """Live guard: anomaly detection + watchlist scoring on the log stream."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg

    config = cfg.load(r)
    log_path = config.get("hosted", {}).get("log_path", "")

    if not log_path:
        con.print("[red]Hosted mode not configured. Run: p hosted init[/red]")
        return

    from patchi.core.hosted import ip_reputation
    from patchi.core.hosted.anomaly import MLDetector, StatisticalDetector
    from patchi.core.hosted.audit_log import write as audit_write
    from patchi.core.hosted.log_parsers import parse_line
    from patchi.core.hosted.watchlist import WatchlistTracker

    stat_detector = StatisticalDetector(config)
    ml_detector = MLDetector()
    escalate_fn = _make_escalation_fn(r, config)
    tracker = WatchlistTracker(r, escalation_fn=escalate_fn)

    con.print()
    con.print(f"[bold #C8621A]Live Guard[/bold #C8621A]  [dim]monitoring {log_path}[/dim]")
    con.print("[dim]Statistical + ML anomaly detection active. Press Ctrl+C to stop.[/dim]")
    con.print()

    sev_colors = {"critical": "#FF4D6D", "high": "#FF8C42", "medium": "#FACC15"}
    log_file = Path(log_path)

    try:
        with _tail_file(log_file) as lines:
            for raw_line in lines:
                entry = parse_line(raw_line)
                if not entry:
                    continue

                # Check IP reputation — flag blocked IPs
                if entry.ip and ip_reputation.is_blocked(entry.ip, r):
                    con.print(
                        f"  [#FF4D6D]BLOCKED  [/#FF4D6D] [dim]{entry.ip}[/dim] — known threat IP"
                    )
                    audit_write(
                        r,
                        "blocked_ip_request",
                        data={
                            "ip": entry.ip,
                            "path": entry.path,
                        },
                    )
                    continue

                findings = stat_detector.feed(entry) + ml_detector.feed(entry)

                for finding in findings:
                    if finding.severity in sev_colors:
                        color = sev_colors[finding.severity]
                        ts = time.strftime("%H:%M:%S")
                        con.print(
                            f"  [{color}]{finding.severity.upper():<8}[/{color}] "
                            f"[dim]{ts}[/dim]  {finding.title}"
                        )
                        if finding.ip:
                            tracker.record(finding.ip, finding.detector, finding.title)
                            ip_reputation.record_hit(finding.ip, finding.detector, r)
                        audit_write(
                            r,
                            "anomaly_detected",
                            data={
                                "detector": finding.detector,
                                "severity": finding.severity,
                                "title": finding.title,
                                "ip": finding.ip,
                            },
                        )

    except KeyboardInterrupt:
        con.print()
        con.print("[dim]Guard stopped.[/dim]")
        con.print()

def _on_escalation(ip: str, score: float, severity: str) -> None:
    """Called by WatchlistTracker when an IP crosses a threshold."""
    color = "#FF4D6D" if severity == "critical" else "#FF8C42"
    con.print(
        f"\n  [{color}]⚠ ESCALATION[/{color}]  IP [bold]{ip}[/bold] "
        f"score={score:.0f}  severity={severity.upper()}"
    )

def _make_escalation_fn(root: Path, config: dict):
    """Create an escalation callback that respects config and sends notifications."""
    escalate_enabled = config.get("hosted", {}).get("escalate", True)

    def _escalation(ip: str, score: float, severity: str) -> None:
        color = "#FF4D6D" if severity == "critical" else "#FF8C42"
        con.print(
f"\n  [{color}]⚠ ESCALATION[/{color}]  IP [bold]{ip}[/bold] "
            f"score={score:.0f}  severity={severity.upper()}"
        )
        if escalate_enabled:
            try:
                from patchi.core.notifications.notifier import Notifier

                n = Notifier(root)
                n.send(
                    severity,
                    f"Hosted mode escalation: IP {ip}",
                    f"IP {ip} escalated to {severity.upper()} (score={score:.0f})",
                )
            except Exception as e:
                _log.warning("_escalation failed: %s", e)

    return _escalation

# ── status ─────────────────────────────────────────────────────────────────────

def run_status(root: Path | None = None, json_output: bool = False) -> None:
    """Show watchlist top threats and audit log summary."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg
    from patchi.core.hosted.audit_log import read_recent
    from patchi.core.hosted.watchlist import WatchlistTracker

    config = cfg.load(r)
    hosted = config.get("hosted", {})
    enabled = hosted.get("enabled", False)
    log_path = hosted.get("log_path", "")

    if json_output:
        import json as _json

        tracker = WatchlistTracker(r)
        top_ips = tracker.top(10) if enabled else []
        entries = read_recent(r, 5) if enabled else []
        print(
            _json.dumps(
                {
                    "enabled": enabled,
                    "log_path": log_path,
                    "log_format": hosted.get("log_format", ""),
                    "top_threats": top_ips,
                    "recent_events": entries,
                },
                indent=2,
            )
        )
        return

    con.print()
    con.print("[bold #C8621A]Hosted Mode Status[/bold #C8621A]")
    con.print()

    status_text = "[#4ADE80]enabled[/#4ADE80]" if enabled else "[#6B7280]not configured[/#6B7280]"
    con.print(f"  Mode:    {status_text}")
    if log_path:
        con.print(f"  Log:     [dim]{log_path}[/dim]")
    con.print()

    if not enabled:
        con.print("[dim]  Run 'p hosted init' to configure hosted mode.[/dim]")
        con.print()
        return

    # Watchlist
    tracker = WatchlistTracker(r)
    top_ips = tracker.top(10)

    if top_ips:
        con.print("[bold #F2EDD6]Top Threat IPs[/bold #F2EDD6]")
        table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
        table.add_column("IP", style="bold", width=18)
        table.add_column("Score", justify="right", width=8)
        table.add_column("Hits", justify="right", width=6)
        table.add_column("Last seen", width=20)

        for ip_data in top_ips:
            score = ip_data.get("current_score", 0)
            hits = ip_data.get("hit_count", 0)
            last = ip_data.get("last_seen", 0)
            last_s = time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "—"
            color = "#FF4D6D" if score >= 100 else "#FF8C42" if score >= 50 else "#FACC15"
            table.add_row(
                ip_data.get("ip", "?"),
                Text(f"{score:.0f}", style=color),
                str(hits),
                last_s,
            )
        con.print(table)
        con.print()

    # Audit log
    entries = read_recent(r, 5)
    if entries:
        con.print("[bold #F2EDD6]Recent Audit Events[/bold #F2EDD6]")
        for e in entries:
            ts = time.strftime("%H:%M:%S", time.localtime(e.get("timestamp", 0)))
            event = e.get("event", "?")
            data = e.get("data", {})
            con.print(f"  [dim]{ts}[/dim]  [bold]{event}[/bold]  [dim]{_fmt_data(data)}[/dim]")
        con.print()

# ── logs ───────────────────────────────────────────────────────────────────────

def run_logs(root: Path | None = None, limit: int = 50) -> None:
    """Stream the Patchi audit log in real time."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.hosted.audit_log import _log_path, read_recent

    log_file = _log_path(r)

    con.print()
    con.print(f"[bold #C8621A]Hosted Audit Log[/bold #C8621A]  [dim]{log_file}[/dim]")
    con.print("[dim]Press Ctrl+C to stop.[/dim]")
    con.print()

    # Show last N entries first
    entries = read_recent(r, limit)
    for e in reversed(entries):
        _print_log_entry(e)

    # Then tail for new ones
    try:
        if log_file.exists():
            with open(log_file, "r", encoding="utf-8") as f:
                f.seek(0, 2)  # seek to end
                while True:
                    line = f.readline()
                    if line:
                        try:
                            import json as _json

                            entry = _json.loads(line)
                            _print_log_entry(entry)
                        except Exception as e:
                            _log.warning("run_logs failed: %s", e)
                    else:
                        time.sleep(0.2)
        else:
            con.print("[dim]Audit log does not exist yet. Start the worker to populate it.[/dim]")
    except KeyboardInterrupt:
        con.print()

def _print_log_entry(entry: dict) -> None:
    ts = time.strftime("%H:%M:%S", time.localtime(entry.get("timestamp", 0)))
    event = entry.get("event", "?")
    actor = entry.get("actor", "")
    data = entry.get("data", {})
    con.print(
        f"  [dim]{ts}[/dim]  [bold #F2EDD6]{event:<20}[/bold #F2EDD6]"
        f"  [dim]{actor}  {_fmt_data(data)}[/dim]"
    )

# ── disconnect ─────────────────────────────────────────────────────────────────

def run_disconnect(root: Path | None = None) -> None:
    """Clear hosted mode config."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    confirmed = Confirm.ask("  Clear hosted mode configuration?", default=False)
    if not confirmed:
        con.print("[dim]Cancelled.[/dim]")
        return

    from patchi.core import config as cfg

    config = cfg.load(r)
    config.pop("hosted", None)
    cfg.save(config, r)

    con.print()
    con.print("[#4ADE80]✓[/#4ADE80] Hosted mode configuration cleared.")
    con.print()

# ── token commands ─────────────────────────────────────────────────────────────

def run_token_add(root: Path | None = None) -> None:
    """Generate a new admin token and show it once."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.hosted.tokens import generate

    name = Prompt.ask("  Token name (label for identification)", default="admin")
    plaintext = generate(r, name)

    con.print()
    con.print("[#4ADE80]✓[/#4ADE80] Admin token generated.")
    con.print()
    con.print(
        Panel(
            f"[bold]{plaintext}[/bold]\n",
            title=f"Token: {name}",
            border_style="#C8621A",
            padding=(1, 2),
        )
    )
    con.print()

def run_token_list(root: Path | None = None) -> None:
    """List all active admin tokens (names only — plaintext is never stored)."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.hosted.tokens import list_tokens

    tokens = list_tokens(r)
    con.print()
    con.print("[bold #C8621A]Admin Tokens[/bold #C8621A]")
    con.print()

    if not tokens:
        con.print("[dim]  No tokens configured. Run: p hosted token add[/dim]")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("ID", width=10)
    table.add_column("Name", style="bold #F2EDD6", width=20)
    table.add_column("Created", width=22)
    table.add_column("Last used", width=22)

    for tok in tokens:
        created = _fmt_ts(tok.get("created_at"))
        last_used = _fmt_ts(tok.get("last_used")) if tok.get("last_used") else "Never"
        table.add_row(tok.get("id", "?"), tok.get("name", "?"), created, last_used)

    con.print(table)
    con.print()

def run_token_revoke(token_id: str, root: Path | None = None) -> None:
    """Revoke a token by ID."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.hosted.audit_log import write as audit_write
    from patchi.core.hosted.tokens import revoke

    ok = revoke(r, token_id)
    con.print()
    if ok:
        audit_write(r, "token_revoked", data={"id": token_id})
        con.print(f"[#4ADE80]✓[/#4ADE80] Token [bold]{token_id}[/bold] revoked.")
    else:
        con.print(f"[yellow]Token {token_id!r} not found.[/yellow]")
    con.print()

# ── daemon ─────────────────────────────────────────────────────────────────────

def run_daemon(root: Path | None = None, guard: bool = False) -> None:
    """
    Start the hosted worker as a daemon with auto-restart, PID management,
    and health checks. Runs in the foreground with auto-restart on crash.
    If guard=True, also runs anomaly detection in the worker loop.
    """
    import signal

    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg

    config = cfg.load(r)
    log_path = config.get("hosted", {}).get("log_path", "")

    if not log_path:
        con.print("[red]Hosted mode not configured. Run: p hosted init[/red]")
        return

    # PID file management
    hosted_dir = r / ".patchi" / "hosted"
    hosted_dir.mkdir(parents=True, exist_ok=True)
    pid_file = hosted_dir / "worker.pid"

    # Check if already running
    if pid_file.exists():
        try:
            old_pid = int(pid_file.read_text().strip())
            # Check if process is still alive
            if platform.system() == "Windows":
                import subprocess

                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {old_pid}"], capture_output=True, text=True
                )
                if str(old_pid) in result.stdout:
                    con.print(f"[yellow]Worker already running (PID {old_pid}).[/yellow]")
                    con.print(
                        "[dim]Run 'p hosted stop' first, or delete .patchi/hosted/worker.pid[/dim]"
                    )
                    return
            else:
                os.kill(old_pid, 0)  # Check if process exists
                con.print(f"[yellow]Worker already running (PID {old_pid}).[/yellow]")
                return
        except (ValueError, ProcessLookupError, OSError):
            pass  # Stale PID file, proceed

    # Write our PID
    pid_file.write_text(str(os.getpid()), encoding="utf-8")

    con.print()
    con.print(f"[bold #C8621A]Hosted Daemon[/bold #C8621A]  [dim]tailing {log_path}[/dim]")
    if guard:
        con.print("[dim]Guard mode: anomaly detection active. Press Ctrl+C to stop.[/dim]")
    else:
        con.print("[dim]Auto-restart enabled. Press Ctrl+C to stop.[/dim]")
    con.print()

    # Graceful shutdown handler
    _shutdown = False

    def _handle_signal(signum, frame):
        nonlocal _shutdown
        _shutdown = True
        con.print("\n[yellow]Shutdown signal received...[/yellow]")

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    # Track health
    last_health_check = time.monotonic()
    last_restart = time.monotonic()
    restart_count = 0
    max_restarts_per_hour = 10

    try:
        while not _shutdown:
            # Health check every 60s
            now = time.monotonic()
            if now - last_health_check >= 60:
                _daemon_health_check(r, restart_count)
                last_health_check = now

            # Rate-limit restarts
            if now - last_restart < 3600 and restart_count >= max_restarts_per_hour:
                con.print(
                    f"[red]Too many restarts ({restart_count}/hour). Waiting 5 minutes...[/red]"
                )
                time.sleep(300)
                restart_count = 0
                last_restart = time.monotonic()
                continue

            # Run worker loop
            try:
                _run_worker_loop(r, log_path, guard=guard)
                # If worker exits normally (EOF), wait and restart
                if not _shutdown:
                    con.print("[dim]Worker exited (EOF). Restarting in 2s...[/dim]")
                    time.sleep(2)
                    restart_count += 1
                    last_restart = time.monotonic()
            except Exception as e:
                if not _shutdown:
                    con.print(f"[red]Worker crashed: {e}[/red]")
                    con.print("[dim]Restarting in 5s...[/dim]")
                    time.sleep(5)
                    restart_count += 1
                    last_restart = time.monotonic()

    finally:
        # Cleanup PID file
        try:
            pid_file.unlink(missing_ok=True)
        except Exception as e:
            _log.warning("run_daemon failed: %s", e)
        con.print(f"[dim]Daemon stopped. {restart_count} restart(s) during this session.[/dim]")

def _run_worker_loop(root: Path, log_path: str, guard: bool = False) -> None:
    """Run the worker's main loop. Returns when log file EOF or shutdown."""
    from patchi.core import config as cfg
    from patchi.core.hosted.audit_log import write as audit_write
    from patchi.core.hosted.log_parsers import parse_line

    stat_detector = None
    ml_detector = None
    tracker = None

    if guard:
        from patchi.core.hosted import ip_reputation
        from patchi.core.hosted.anomaly import MLDetector, StatisticalDetector
        from patchi.core.hosted.watchlist import WatchlistTracker

        config = cfg.load(root)
        stat_detector = StatisticalDetector(config)
        ml_detector = MLDetector()
        escalate_fn = _make_escalation_fn(root, config)
        tracker = WatchlistTracker(root, escalation_fn=escalate_fn)

    lines_parsed = 0
    lines_failed = 0
    last_report = time.monotonic()
    last_activity = time.monotonic()

    log_file = Path(log_path)
    with _tail_file(log_file) as lines:
        for raw_line in lines:
            entry = parse_line(raw_line)
            if entry:
                lines_parsed += 1
                last_activity = time.monotonic()
                audit_write(
                    root,
                    "log_line",
                    data={
                        "method": entry.method,
                        "path": entry.path,
                        "status": entry.status,
                        "ip": entry.ip,
                        "source": entry.source,
                    },
                )
                # Guard mode: run anomaly detection
                if guard and stat_detector:
                    if entry.ip and ip_reputation.is_blocked(entry.ip, root):
                        audit_write(
                            root,
                            "blocked_ip_request",
                            data={
                                "ip": entry.ip,
                                "path": entry.path,
                            },
                        )
                    else:
                        findings = stat_detector.feed(entry) + ml_detector.feed(entry)
                        for finding in findings:
                            if finding.ip:
                                tracker.record(finding.ip, finding.detector, finding.title)
                                ip_reputation.record_hit(finding.ip, finding.detector, root)
                            audit_write(
                                root,
                                "anomaly_detected",
                                data={
                                    "detector": finding.detector,
                                    "severity": finding.severity,
                                    "title": finding.title,
                                    "ip": finding.ip,
                                },
                            )
            else:
                lines_failed += 1

            # Progress every 30s (less spam for daemon mode)
            now = time.monotonic()
            if now - last_report >= 30:
                con.print(
                    f"  [dim]parsed {lines_parsed} lines  |  "
                    f"unrecognised {lines_failed}  |  "
                    f"last activity {int(now - last_activity)}s ago[/dim]"
                )
                last_report = now

def _daemon_health_check(root: Path, restart_count: int) -> None:
    """Periodic health check for the daemon."""
    try:
        import psutil

        pid = os.getpid()
        proc = psutil.Process(pid)
        mem_mb = proc.memory_info().rss / (1024 * 1024)
        cpu_pct = proc.cpu_percent(interval=0.1)
        con.print(
            f"  [dim]health: mem {mem_mb:.0f}MB  cpu {cpu_pct:.1f}%  restarts {restart_count}[/dim]"
        )
    except ImportError:
        # psutil not available, basic check
        con.print(f"  [dim]health: pid {os.getpid()}  restarts {restart_count}[/dim]")
    except Exception as e:
        _log.warning("_daemon_health_check failed: %s", e)

# ── stop ───────────────────────────────────────────────────────────────────────

def run_stop(root: Path | None = None) -> None:
    """Stop a running daemon by PID file."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    pid_file = r / ".patchi" / "hosted" / "worker.pid"
    if not pid_file.exists():
        con.print("[dim]No running daemon found.[/dim]")
        return

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        con.print("[dim]Invalid PID file. Cleaning up.[/dim]")
        pid_file.unlink(missing_ok=True)
        return

    try:
        if platform.system() == "Windows":
            import subprocess

            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
        else:
            import signal

            os.kill(pid, signal.SIGTERM)
        con.print(f"[#4ADE80]✓[/#4ADE80] Sent stop signal to PID {pid}")
    except ProcessLookupError:
        con.print(f"[dim]Process {pid} not found. Cleaning up PID file.[/dim]")
    except Exception as e:
        con.print(f"[red]Failed to stop: {e}[/red]")
    finally:
        pid_file.unlink(missing_ok=True)

# ── block / unblock ───────────────────────────────────────────────────────────

def run_block(ip: str, root: Path | None = None) -> None:
    """Manually block an IP address."""
    if not ip:
        con.print("[red]Usage: p hosted block <ip>[/red]")
        return
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return
    from patchi.core.hosted import ip_reputation
    from patchi.core.hosted.audit_log import write as audit_write

    ip_reputation.block(ip, r)
    audit_write(r, "ip_blocked", data={"ip": ip, "reason": "manual"})
    con.print(f"[#4ADE80]✓[/#4ADE80] IP [bold]{ip}[/bold] blocked.")

def run_unblock(ip: str, root: Path | None = None) -> None:
    """Unblock an IP address."""
    if not ip:
        con.print("[red]Usage: p hosted unblock <ip>[/red]")
        return
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return
    from patchi.core.hosted import ip_reputation
    from patchi.core.hosted.audit_log import write as audit_write

    ok = ip_reputation.unblock(ip, r)
    if ok:
        audit_write(r, "ip_unblocked", data={"ip": ip})
        con.print(f"[#4ADE80]✓[/#4ADE80] IP [bold]{ip}[/bold] unblocked.")
    else:
        con.print(f"[dim]IP {ip} was not blocked.[/dim]")

# ── Utilities ──────────────────────────────────────────────────────────────────

def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

def _fmt_data(data: dict) -> str:
    parts = []
    for k, v in list(data.items())[:3]:
        parts.append(f"{k}={v!r}")
    return "  ".join(parts)

def _tail_file(path: Path):
    """
    Context manager that yields lines from a file, blocking when caught up.
    If file does not exist, waits for it to appear (up to 30s).
    Handles log file rotation by detecting inode/size changes.
    """

    class _Tailer:
        def __enter__(self_inner):
            waited = 0
            while not path.exists() and waited < 30:
                time.sleep(1)
                waited += 1
            if not path.exists():
                raise FileNotFoundError(f"Log file still not found after 30s: {path}")
            self_inner._f = open(path, "r", encoding="utf-8", errors="replace")
            self_inner._f.seek(0, 2)  # jump to end
            try:
                self_inner._inode = path.stat().st_ino
                self_inner._size = path.stat().st_size
            except OSError:
                self_inner._inode = None
                self_inner._size = 0
            return self_inner

        def __exit__(self_inner, *args):
            self_inner._f.close()

        def _check_rotation(self_inner):
            try:
                stat = path.stat()
                if self_inner._inode is not None and stat.st_ino != self_inner._inode:
                    self_inner._f.close()
                    self_inner._f = open(path, "r", encoding="utf-8", errors="replace")
                    self_inner._inode = stat.st_ino
                    self_inner._size = stat.st_size
                elif stat.st_size < self_inner._size:
                    self_inner._f.close()
                    self_inner._f = open(path, "r", encoding="utf-8", errors="replace")
                    self_inner._inode = stat.st_ino
                    self_inner._size = stat.st_size
                else:
                    self_inner._size = stat.st_size
            except OSError:
                pass

        def __iter__(self_inner):
            while True:
                line = self_inner._f.readline()
                if line:
                    yield line
                else:
                    self_inner._check_rotation()
                    time.sleep(0.1)

    return _Tailer()