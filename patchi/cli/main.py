import argparse
import logging
import sys

from patchi import __version__
from patchi.cli.console import con

"""
Patchi CLI — main entry point.

Argparse wiring + dispatch are fully registry-driven (§3 Command Unification):
parser subparsers are built from patchi.cli.registry.COMMANDS and every
command resolves through it — there is no elif dispatch ladder left. Lazy
imports happen inside the registry framework (dotted "module:handler" paths),
so cold start stays fast regardless of how many commands are registered.
"""


# ── Lazy imports (only load what's needed for the called command) ──────────────


_log = logging.getLogger("patchi.cli.main")


def _cmd_status():
    from patchi.cli.commands.status_cmd import run

    return run


# ── Upcoming stub ──────────────────────────────────────────────────────────────


def _coming_soon(command: str, phase: str) -> None:
    con.print(f"[dim]{command}[/dim] [yellow]→[/yellow] [dim]Coming in {phase}. Not yet available in this build.[/dim]")


# ── Parser setup ───────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patchi",
        description="An intelligent agent that scans, fixes, secures, and guards your app.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Short alias: p   |   Docs: patchi.dev",
    )

    parser.add_argument("--version", action="version", version=f"Patchi v{__version__}")
    parser.add_argument("--no-logo", action="store_true", help="Skip logo draw sequence (for CI)")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of rich format")
    parser.add_argument("--quiet", action="store_true", help="Errors only")
    parser.add_argument("--verbose", action="store_true", help="Show agent reasoning and full detail")
    parser.add_argument("--dry-run", action="store_true", help="Preview actions without executing")
    parser.add_argument(
        "--theme",
        default=None,
        choices=("dark", "light", "mono", "highcontrast"),
        help="CLI color palette (default: value from settings, or dark)",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable color output (same as NO_COLOR env)")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ── registry-driven commands (§3 Command Unification) ──────────────────────
    # Every `p <command>` is declared in patchi.cli.registry.COMMANDS and built
    # here — the legacy argparse blocks and the elif dispatch ladder are gone,
    # so the parser and the router can never drift apart.
    from patchi.cli.framework import register_commands
    from patchi.cli.registry import COMMANDS

    register_commands(sub, COMMANDS)
    return parser


# ── Router ─────────────────────────────────────────────────────────────────────


def _load_patchi_env() -> None:
    """
    Load .patchi/.env into os.environ (non-destructive — never overwrites shell env).
    Called on every CLI invocation before any command runs.
    """
    import os

    from patchi.core.config import find_project_root

    root = find_project_root()
    if root is None:
        return
    env_file = root / ".patchi" / ".env"
    keys_file = root / ".patchi" / "keys.json"

    # Load .env file if it exists
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                if key and key not in os.environ:
                    os.environ[key] = value.strip()
        except OSError:
            pass

    # Load JSON keys file if it exists
    if keys_file.exists():
        try:
            import json
            import os

            data = json.loads(keys_file.read_text(encoding="utf-8"))
            for k, v in data.items():
                if k and k not in os.environ:
                    os.environ[k] = str(v)
        except Exception as e:
            _log.warning("_load_patchi_env failed: %s", e)


def main() -> None:
    # Force UTF-8 encoding on Windows to support Unicode characters (✓, etc.)
    import os

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    # Configure loguru: remove default handler and re-add without ANSI colors
    # when stderr is not a terminal (piped output, pre-commit hooks, CI, etc.)
    from loguru import logger as _loguru_logger

    _loguru_logger.remove()
    _loguru_logger.add(
        sys.stderr,
        colorize=sys.stderr.isatty(),
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        level="DEBUG",
    )

    parser = _build_parser()
    args = parser.parse_args()

    getattr(args, "no_logo", False)

    # Apply the CLI theme before ANY command output happens, so every command
    # (including the "no command -> show status" default path below) is
    # themed consistently with zero per-command wiring.
    from patchi.cli.console import configure_theme

    configure_theme(
        explicit=getattr(args, "theme", None),
        no_color_flag=getattr(args, "no_color", False),
        json_mode=getattr(args, "json", False),
    )

    # Auto-load .patchi/.env into os.environ on every command invocation.
    # Keys are only set if not already present — never overwrite shell env.
    _load_patchi_env()

    # No command → show status if project exists, else show help
    if not args.command:
        from patchi.core.config import find_project_root

        if find_project_root():
            _cmd_status()(root=None)
        else:
            parser.print_help()
        return

    cmd = args.command

    # Auto-update check (background, weekly)
    import threading

    from patchi.cli.commands.update_cmd import auto_check_background

    threading.Thread(target=auto_check_background, daemon=True).start()

    # Onboarding check (M-01): if project exists but onboarding not complete,
    # and the user didn't explicitly run `init`, prompt them to run it.
    # Never in --json mode: stdout must stay machine-parseable (banner corrupts
    # every `p <cmd> --json` consumer otherwise). Subcommand-level --json lives
    # on json_output (subparsers don't inherit top-level dests), so check both.
    if cmd != "init" and not (
        getattr(args, "json", False) or getattr(args, "json_output", False)
    ):
        try:
            from patchi.core.config import find_project_root, load

            r = find_project_root()
            if r:
                conf = load(r)
                if not conf.get("onboarding_complete", False):
                    con.print()
                    con.print("[bold #C8621A]Welcome to Patchi![/bold #C8621A]")
                    con.print("[dim]It looks like you haven't completed setup yet.[/dim]")
                    con.print("[dim]Run [bold]p init[/bold] to configure your project.[/dim]")
                    con.print()
                    sys.stdout.flush()
        except Exception as e:
            _log.warning("main failed: %s", e)

    # ── registry-driven dispatch (§3 Command Unification) ──────────────────────
    # The registry IS the router: every subparser resolves through COMMANDS, so
    # there is no fall-through ladder anymore.
    from patchi.cli.framework import dispatch as _registry_dispatch
    from patchi.cli.registry import COMMANDS as _REGISTRY_COMMANDS

    _result, _handled = _registry_dispatch(_REGISTRY_COMMANDS, args)

    # After command dispatch, show update notification if available
    if cmd and cmd != "update":
        from patchi.cli.commands.update_cmd import print_update_available_if_needed

        try:
            print_update_available_if_needed()
        except Exception as e:
            _log.warning("main failed: %s", e)

    if _handled:
        return _result

    parser.print_help()
    return None


if __name__ == "__main__":
    sys.exit(main() or 0)
