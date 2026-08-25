"""
`p model` — Manage Patchi's local Ollama model integration.

Subcommands:
  p model set <model_name>   — Set the local model Patchi uses
  p model list               — List available models from Ollama
  p model status             — Show current model + Ollama connection health

Ollama API base: http://localhost:11434
All network calls time out in 5s — they are informational checks, not blockers.
"""

from __future__ import annotations

# ── Subcommand runners ─────────────────────────────────────────────────────────
import logging
import time
from pathlib import Path

from rich.table import Table

from patchi.cli.console import con
from patchi.core.config import require_project_root
from patchi.core.constants import OLLAMA_BASE_URL

_log = logging.getLogger("patchi.cli.model_cmd")


def run_set(model_name: str, root: Path | None = None) -> None:
    """Set the local model Patchi will use."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import config as cfg

    cfg.set_value("ai.local_model_name", model_name, r)
    con.print()
    con.print(f"[#4ADE80]✓[/#4ADE80] Local model set to [bold]{model_name}[/bold]")
    con.print()

    # Quick availability check
    ok, note = _model_available(model_name)
    if ok:
        con.print(f"  [dim]✓ {note}[/dim]")
    else:
        con.print(f"  [#FACC15]⚠ {note}[/#FACC15]")
    con.print()


def run_list(root: Path | None = None) -> None:
    """List models available from local Ollama instance."""
    con.print()
    con.print("[bold #C8621A]Local Models[/bold #C8621A]  [dim]from Ollama (localhost:11434)[/dim]")
    con.print()

    try:
        r = root or require_project_root()
        from patchi.core import config as cfg

        current_model = cfg.load(r).get("ai", {}).get("local_model_name", "")
    except Exception as e:
        _log.warning("run_list failed: %s", e)
        current_model = ""

    models = _fetch_models()

    if models is None:
        con.print("[#FACC15]⚠  Ollama is not running.[/#FACC15]")
        con.print("[dim]Start it with: ollama serve[/dim]")
        con.print()
        return

    if not models:
        con.print("[dim]No models pulled yet.[/dim]")
        con.print("[dim]Try: ollama pull llama3.2[/dim]")
        con.print()
        return

    table = Table(show_header=True, header_style="bold #C8621A", box=None, pad_edge=False)
    table.add_column("Model", style="bold #F2EDD6", width=32)
    table.add_column("Size", justify="right", width=10)
    table.add_column("Modified", width=22)
    table.add_column("Active", width=8)

    for m in sorted(models, key=lambda x: x.get("name", "")):
        name = m.get("name", "?")
        size = _fmt_size(m.get("size", 0))
        mod = m.get("modified_at", "")[:19].replace("T", " ")
        active = (
            "[#4ADE80]●[/#4ADE80]"
            if name.split(":")[0] == (current_model or "").split(":")[0]
            else ""
        )
        table.add_row(name, size, mod, active)

    con.print(table)
    con.print()


def run_status(root: Path | None = None) -> None:
    """Show Ollama connection health and current model."""
    con.print()
    con.print("[bold #C8621A]Model Status[/bold #C8621A]")
    con.print()

    try:
        r = root or require_project_root()
        from patchi.core import config as cfg

        config = cfg.load(r)
        local_model = config.get("ai", {}).get("local_model_name")
    except RuntimeError:
        local_model = None

    # ── Ollama health ─────────────────────────────────────────────────────────
    ollama_ok, ollama_note = _check_ollama()
    marker = "[#4ADE80]●[/#4ADE80]" if ollama_ok else "[#FF4D6D]●[/#FF4D6D]"
    con.print(f"  {marker} Ollama   [dim]{ollama_note}[/dim]")

    # ── Configured model ──────────────────────────────────────────────────────
    if local_model:
        avail_ok, avail_note = _model_available(local_model)
        marker2 = "[#4ADE80]●[/#4ADE80]" if avail_ok else "[#FACC15]●[/#FACC15]"
        con.print(f"  {marker2} Model    [bold]{local_model}[/bold]  [dim]{avail_note}[/dim]")

        # Benchmark ping if available
        if ollama_ok:
            ms = _ping_model(local_model)
            if ms is not None:
                con.print(f"  [dim]         Response time: {ms}ms[/dim]")
    else:
        con.print("  [dim]—  No local model configured. Run: p model set <name>[/dim]")

    con.print()


# ── Ollama API helpers ─────────────────────────────────────────────────────────


def _fetch_models() -> list[dict] | None:
    """Return list of pulled model objects, or None if Ollama is unreachable."""
    try:
        import httpx

        resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=4.0)
        if resp.status_code == 200:
            return resp.json().get("models", [])
        return []
    except Exception as e:
        _log.warning("_fetch_models failed: %s", e)
        return None


def _check_ollama() -> tuple[bool, str]:
    try:
        import httpx

        t0 = time.monotonic()
        resp = httpx.get(f"{OLLAMA_BASE_URL}/", timeout=4.0)
        ms = int((time.monotonic() - t0) * 1000)
        if resp.status_code in (200, 404):
            return True, f"Running — localhost:11434 ({ms}ms)"
        return False, f"HTTP {resp.status_code}"
    except Exception as e:
        _log.debug("_check_ollama failed: %s", e)
        return False, "Not running — start with: ollama serve"


def _model_available(model_name: str) -> tuple[bool, str]:
    models = _fetch_models()
    if models is None:
        return False, "Ollama not running"
    stem = model_name.split(":")[0]
    if any(m.get("name", "").split(":")[0] == stem for m in models):
        return True, "Model is available locally"
    return False, f"Not pulled — run: ollama pull {model_name}"


def _ping_model(model_name: str) -> int | None:
    """Send a minimal generation request to measure first-token latency."""
    try:
        import httpx

        t0 = time.monotonic()
        resp = httpx.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={"model": model_name, "prompt": "hi", "stream": False, "max_tokens": 1},
            timeout=15.0,
        )
        ms = int((time.monotonic() - t0) * 1000)
        if resp.status_code == 200:
            return ms
        return None
    except Exception as e:
        _log.debug("_ping_model failed: %s", e)
        return None


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1_073_741_824:
        return f"{size_bytes / 1_073_741_824:.1f} GB"
    if size_bytes >= 1_048_576:
        return f"{size_bytes / 1_048_576:.0f} MB"
    return f"{size_bytes} B"
