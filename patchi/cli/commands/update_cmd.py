"""
`p update` — Check for and apply updates to Patchi.

Usage:
  p update               — check for updates, prompt to install if newer available
  p update --check       — check only, no install prompt
  p update --force       — force reinstall/refresh current version
  p update --auto        — auto-install without prompting (for CI/scripts)

Auto-update check:
  On startup, Patchi checks for updates silently once per week.
  A notification is shown on the next command if a newer version exists.
"""
from __future__ import annotations

import json
import logging

# ── Config ────────────────────────────────────────────────────────────────────
import os
import sys
import time
from pathlib import Path

from rich.prompt import Confirm

from patchi import __version__
from patchi.cli.console import con

UPDATE_SOURCE: dict[str, str] = {
    "type": "github",
    "owner": os.environ.get("PATCHI_UPDATE_OWNER", ""),
    "repo": os.environ.get("PATCHI_UPDATE_REPO", "patchi"),
    "pip_name": os.environ.get("PATCHI_PIP_NAME", "patchi"),
}

CHECK_FILE = ".patchi/update_check.json"
CHECK_INTERVAL_DAYS = 7


# ── Public entry points ───────────────────────────────────────────────────────


_log = logging.getLogger("patchi.cli.update_cmd")


def run(
    check: bool = False,
    force: bool = False,
    auto: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p update`."""
    from patchi.core.config import require_project_root

    try:
        r = root or require_project_root()
    except RuntimeError:
        r = Path.cwd()

    if force:
        _force_reinstall(r)
        return

    if check:
        _check_only(r)
        return

    # Full check + prompt to install
    info = _fetch_latest(r)
    if info is None:
        return

    latest = info.get("version", "")
    if not latest or not _is_newer(latest, __version__):
        con.print(f"[#4ADE80]Already up to date:[/#4ADE80] v{__version__}")
        return

    _print_release_info(info)
    if auto:
        _do_install(r, info)
    else:
        if Confirm.ask(f"Update to v{latest}?", default=True):
            _do_install(r, info)


def run_check(root: Path | None = None) -> dict | None:
    """Silent check — called from background thread. Returns update info or None."""
    from patchi.core.config import require_project_root

    try:
        r = root or require_project_root()
    except RuntimeError:
        r = Path.cwd()
    try:
        return _fetch_latest(r, silent=True)
    except Exception as e:
        _log.warning("run_check failed: %s", e)
        return None


# ── Auto-update check (called from main.py on startup) ────────────────────────


def auto_check_background(root: Path | None = None) -> None:
    """
    Background thread target: checks for updates once per week.
    Stores result in .patchi/update_check.json for display on next command.
    """
    from patchi.core.config import require_project_root

    try:
        r = root or require_project_root()
    except RuntimeError:
        r = Path.cwd()

    check_path = r / CHECK_FILE
    try:
        if check_path.exists():
            data = json.loads(check_path.read_text(encoding="utf-8"))
            last = data.get("last_check", 0)
            if time.time() - last < CHECK_INTERVAL_DAYS * 86400:
                return  # too soon
    except Exception as e:
        _log.warning("auto_check_background failed: %s", e)

    try:
        info = _fetch_latest(r, silent=True)
        if info:
            check_path.parent.mkdir(parents=True, exist_ok=True)
            check_path.write_text(json.dumps({**info, "last_check": time.time()}), encoding="utf-8")
    except Exception as e:
        _log.warning("auto_check_background failed: %s", e)


def print_update_available_if_needed(root: Path | None = None) -> None:
    """Called by main.py after command dispatch — shows notification if update available."""
    from patchi.core.config import require_project_root

    try:
        r = root or require_project_root()
    except RuntimeError:
        r = Path.cwd()

    check_path = r / CHECK_FILE
    if not check_path.exists():
        return
    try:
        data = json.loads(check_path.read_text(encoding="utf-8"))
        latest = data.get("version", "")
        if latest and _is_newer(latest, __version__):
            con.print(
                f"  [dim]Update available:[/dim] [#A78BFA]v{latest}[/#A78BFA] "
                f"[dim](run 'p update')[/dim]"
            )
    except Exception as e:
        _log.warning("print_update_available_if_needed failed: %s", e)


# ── Core logic ────────────────────────────────────────────────────────────────


def _fetch_latest(root: Path, silent: bool = False) -> dict | None:
    """Fetch latest version info from GitHub releases."""
    import httpx

    owner = UPDATE_SOURCE.get("owner", "")
    repo = UPDATE_SOURCE.get("repo", "patchi")
    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"

    if not owner:
        if not silent:
            con.print("[yellow]Update source not configured yet.[/yellow]")
            con.print("[dim]Set the PATCHI_UPDATE_OWNER environment variable.[/dim]")
        return None

    try:
        resp = httpx.get(api_url, timeout=10, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name", "").lstrip("v")
        return {
            "version": tag,
            "tag_name": data.get("tag_name", ""),
            "release_url": data.get("html_url", ""),
            "body": (data.get("body", "") or "")[:500],
            "assets": data.get("assets", []),
        }
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            if not silent:
                con.print("[yellow]GitHub API rate limit hit. Try again later.[/yellow]")
        elif e.response.status_code == 404:
            if not silent:
                con.print("[yellow]No releases found yet.[/yellow]")
        else:
            if not silent:
                con.print(f"[red]Failed to check updates: {e}[/red]")
    except httpx.RequestError as e:
        if not silent:
            con.print(f"[yellow]Could not reach GitHub: {e}[/yellow]")
    except Exception as e:
        if not silent:
            con.print(f"[red]Update check failed: {e}[/red]")
    return None


def _is_newer(latest: str, current: str) -> bool:
    """Return True if latest > current (semver comparison)."""
    try:
        l_parts = [int(x) for x in latest.split(".")]
        c_parts = [int(x) for x in current.split(".")]
        # Pad to same length
        while len(l_parts) < 3:
            l_parts.append(0)
        while len(c_parts) < 3:
            c_parts.append(0)
        return l_parts > c_parts
    except (ValueError, AttributeError):
        # Fall back to string comparison
        return latest > current


# ── UI helpers ────────────────────────────────────────────────────────────────


def _print_release_info(info: dict) -> None:
    """Print release details."""
    version = info.get("version", "?")
    body = (info.get("body") or "")[:300]
    url = info.get("release_url", "")

    con.print()
    con.print(
        f"[bold #A78BFA]Update available:[/bold #A78BFA] v{__version__} [dim]→[/dim] [bold]v{version}[/bold]"
    )
    if body:
        con.print()
        for line in body.splitlines()[:8]:
            con.print(f"  [dim]{line}[/dim]")
    if url:
        con.print()
        con.print(f"  [link={url}]{url}[/link]")
    con.print()


def _check_only(root: Path) -> None:
    """Just check, no install."""
    info = _fetch_latest(root)
    if info is None:
        return

    latest = info.get("version", "")
    if not latest or _is_newer(latest, __version__):
        con.print(f"[#4ADE80]Already up to date:[/#4ADE80] v{__version__}")
    else:
        _print_release_info(info)


# ── Install logic ─────────────────────────────────────────────────────────────


def _do_install(root: Path, info: dict) -> None:
    """Download and install the latest version."""
    from patchi.cli.display.live_progress import LiveProgress

    pip_name = UPDATE_SOURCE.get("pip_name", "patchi")
    version = info.get("version", "")

    lp = LiveProgress(con, title="Updating")
    lp.start()
    lp.log(f"  Updating to v{version} via pip…")
    lp.update()

    try:
        import subprocess

        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", pip_name],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            lp.log("  [#4ADE80]Update complete![/#4ADE80]")
            lp.update()
            lp.stop(summary=f"Updated to v{version}")

            # Clear cached check so next run re-verifies
            check_path = root / CHECK_FILE
            if check_path.exists():
                check_path.unlink()

            con.print()
            con.print(
                f"[#4ADE80]✓[/#4ADE80] Patchi updated to [bold]v{version}[/bold]. "
                "[dim]Restart your shell to use the new version.[/dim]"
            )
        else:
            lp.log(f"  [red]pip install failed: {result.stderr[:200]}[/red]")
            lp.stop(summary="Update failed")
            con.print(f"[red]Update failed:[/red] {result.stderr[:300]}")
    except FileNotFoundError:
        lp.stop(summary="pip not found")
        con.print("[red]pip not found. Install pip first, then run:[/red]")
        con.print(f"  [bold]pip install --upgrade {pip_name}[/bold]")
    except subprocess.TimeoutExpired:
        lp.stop(summary="pip timed out")
        con.print("[red]pip install timed out after 120s.[/red]")
    except Exception as e:
        lp.stop(summary=f"Update failed: {e}")
        con.print(f"[red]Update failed: {e}[/red]")


def _force_reinstall(root: Path) -> None:
    """Force reinstall current version (--force)."""
    pip_name = UPDATE_SOURCE.get("pip_name", "patchi")
    from patchi.cli.display.live_progress import LiveProgress

    lp = LiveProgress(con, title="Reinstalling")
    lp.start()
    lp.log(f"  Reinstalling {pip_name} v{__version__}…")
    lp.update()

    try:
        import subprocess

        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--force-reinstall", pip_name],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            lp.stop(summary=f"Reinstalled v{__version__}")
            con.print(f"[#4ADE80]✓[/#4ADE80] Patchi v{__version__} reinstalled.")
        else:
            lp.stop(summary="Reinstall failed")
            con.print(f"[red]Reinstall failed:[/red] {result.stderr[:300]}")
    except FileNotFoundError:
        lp.stop(summary="pip not found")
        con.print("[red]pip not found.[/red]")
    except Exception as e:
        lp.stop(summary=f"Reinstall failed: {e}")
        con.print(f"[red]Reinstall failed: {e}[/red]")
