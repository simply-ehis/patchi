"""
`p doctor` — Validate Patchi setup, dependencies, and AI connections.

Checks:
  1. Python version (≥ 3.11 required)
  2. Required Patchi dependencies (rich, watchfiles, vulture, etc.)
  3. Optional test tooling (pytest, playwright, locust)
  4. Optional security tooling (bandit, semgrep)
  5. Project root (.patchi/config.json exists)
  6. API keys — config presence + live connection test
  7. Ollama local model (if configured)
"""

from __future__ import annotations

import importlib
import shutil
import sys

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from patchi.cli.console import con

# ── Dependency manifests ───────────────────────────────────────────────────────

_REQUIRED: list[tuple[str, str, str]] = [
    # (import_name, pip_name, description)
    ("rich", "rich", "Terminal UI rendering"),
    ("watchfiles", "watchfiles", "File watcher (p watch)"),
    ("vulture", "vulture", "Dead code detection"),
    ("httpx", "httpx", "HTTP client (AI requests)"),
    ("fastapi", "fastapi", "Web dashboard backend"),
    ("uvicorn", "uvicorn", "Web dashboard ASGI server"),
    ("psutil", "psutil", "Process + system metrics"),
    ("yaml", "pyyaml", "YAML config parsing"),
    ("loguru", "loguru", "Structured logging"),
]

_OPTIONAL_TEST: list[tuple[str, str, str, str]] = [
    # (command_name, import_name, pip_name, description)
    ("pytest", "pytest", "pytest", "Unit test runner (p test unit)"),
    ("npx", "", "node/npm", "Playwright host (p test browser)"),
    ("locust", "locust", "locust", "Stress test runner (p test stress)"),
    ("pa11y", "", "pa11y", "Accessibility checks (p test accessibility)"),
]

_OPTIONAL_SECURITY: list[tuple[str, str, str, str]] = [
    ("bandit", "bandit", "bandit", "Python security linter"),
    ("semgrep", "", "semgrep", "Multi-language SAST scanner"),
    ("codeql", "", "codeql", "CodeQL semantic analysis"),
    ("pyre", "", "pyre-check fb-sapp", "Pyre/Pysa type + taint analysis"),
    ("safety", "safety", "safety", "Dependency CVE checker"),
    ("pip-audit", "", "pip-audit", "Dependency audit (p security deps)"),
]

# ── Main entry point ───────────────────────────────────────────────────────────

import logging

_log = logging.getLogger("patchi.cli.doctor_cmd")

def run(verbose: bool = False) -> None:
    """Entry point for `p doctor`."""
    con.print()
    con.print("[bold #C8621A]Patchi Doctor[/bold #C8621A]  [dim]system health check[/dim]")
    con.print()

    checks: list[tuple[str, str, str, str]] = []  # (label, status, note, color)
    warnings = 0
    errors = 0

    # ── 1. Python version ─────────────────────────────────────────────────────
    pyver = sys.version_info
    if pyver >= (3, 11):
        checks.append(("Python", "✓", f"{pyver.major}.{pyver.minor}.{pyver.micro}", "#4ADE80"))
    else:
        checks.append(("Python", "✗", f"{pyver.major}.{pyver.minor} — requires ≥ 3.11", "#FF4D6D"))
        errors += 1

    # ── 2. Required dependencies ──────────────────────────────────────────────
    for import_name, pip_name, desc in _REQUIRED:
        ok = _can_import(import_name)
        if ok:
            checks.append((f"dep: {pip_name}", "✓", desc, "#4ADE80"))
        else:
            checks.append((f"dep: {pip_name}", "✗", f"Missing — pip install {pip_name}", "#FF4D6D"))
            errors += 1

    # ── 3. Project root ───────────────────────────────────────────────────────
    try:
        from patchi.core.config import find_project_root

        root = find_project_root()
        if root:
            checks.append(("Project root", "✓", str(root), "#4ADE80"))
        else:
            checks.append(("Project root", "⚠", "Not found — run 'p init' first", "#FACC15"))
            warnings += 1
    except Exception as e:
        checks.append(("Project root", "✗", str(e)[:60], "#FF4D6D"))
        errors += 1
        root = None

    # ── 4. API keys ───────────────────────────────────────────────────────────
    if root:
        try:
            from patchi.core import config as cfg

            config = cfg.load(root)
            ai_keys = config.get("ai", {}).get("keys", [])
            if ai_keys:
                checks.append(("API keys", "✓", f"{len(ai_keys)} key(s) configured", "#4ADE80"))
                # Live test
                for key_entry in ai_keys[:1]:  # test first key only
                    ok, note = _test_api_key(key_entry)
                    color = "#4ADE80" if ok else "#FACC15"
                    status = "✓" if ok else "⚠"
                    checks.append(("  API connection", status, note, color))
                    if not ok:
                        warnings += 1
            else:
                checks.append(("API keys", "⚠", "No keys — run 'p key add'", "#FACC15"))
                warnings += 1
        except Exception as e:
            checks.append(("API keys", "✗", str(e)[:60], "#FF4D6D"))
            errors += 1

    # ── 5. Local model (Ollama) ───────────────────────────────────────────────
    if root:
        try:
            from patchi.core import config as cfg

            local_model = cfg.load(root).get("ai", {}).get("local_model_name")
            if local_model:
                ok, note = _test_ollama(local_model)
                color = "#4ADE80" if ok else "#FACC15"
                status = "✓" if ok else "⚠"
                checks.append((f"Ollama: {local_model}", status, note, color))
                if not ok:
                    warnings += 1
            else:
                checks.append(("Ollama", "—", "No local model configured (optional)", "#6B7280"))
        except Exception as e:
            _log.warning("run failed: %s", e)

    # ── 5b. Config validation ────────────────────────────────────────────────
    if root:
        try:
            from patchi.core import config as cfg

            config = cfg.load(root)

            # Valid mode
            mode_val = config.get("mode", "")
            if mode_val in ("confirm", "auto", "autopilot"):
                checks.append(("Config: mode", "✓", mode_val, "#4ADE80"))
            else:
                checks.append(
                    (
                        "Config: mode",
                        "✗",
                        f"Invalid mode '{mode_val}' — must be confirm/auto/autopilot",
                        "#FF4D6D",
                    )
                )
                errors += 1

            # Valid device_tier
            tier_val = config.get("device_tier", "")
            if tier_val in ("low", "mid", "high"):
                checks.append(("Config: device_tier", "✓", tier_val, "#4ADE80"))
            else:
                checks.append(
                    (
                        "Config: device_tier",
                        "✗",
                        f"Invalid tier '{tier_val}' — must be low/mid/high",
                        "#FF4D6D",
                    )
                )
                errors += 1

            # risk_threshold range
            risk_val = config.get("risk_threshold")
            if risk_val is not None:
                try:
                    risk_num = int(risk_val)
                    if 0 <= risk_num <= 100:
                        checks.append(("Config: risk_threshold", "✓", str(risk_num), "#4ADE80"))
                    else:
                        checks.append(
                            (
                                "Config: risk_threshold",
                                "✗",
                                f"{risk_num} — must be 0–100",
                                "#FF4D6D",
                            )
                        )
                        errors += 1
                except (ValueError, TypeError):
                    checks.append(
                        (
                            "Config: risk_threshold",
                            "✗",
                            f"'{risk_val}' — not a valid integer",
                            "#FF4D6D",
                        )
                    )
                    errors += 1

            # AI key env_var validation
            ai_keys = config.get("ai", {}).get("keys", [])
            for key_entry in ai_keys:
                env_var = key_entry.get("env_var", "")
                nickname = key_entry.get("nickname", key_entry.get("name", "unknown"))
                if env_var:
                    import os

                    if env_var in os.environ:
                        checks.append((f"Key: {nickname}", "✓", f"env {env_var} set", "#4ADE80"))
                    else:
                        checks.append(
                            (f"Key: {nickname}", "⚠", f"env {env_var} not set in shell", "#FACC15")
                        )
                        warnings += 1

            # Validate .patchi/ast_cache.json
            ast_cache = root / ".patchi" / "ast_cache.json"
            if ast_cache.exists():
                try:
                    import json

                    json.loads(ast_cache.read_text(encoding="utf-8"))
                    checks.append(("AST cache", "✓", "Valid JSON", "#4ADE80"))
                except (json.JSONDecodeError, ValueError) as e:
                    checks.append(("AST cache", "✗", f"Invalid JSON: {str(e)[:40]}", "#FF4D6D"))
                    errors += 1
            else:
                checks.append(
                    ("AST cache", "—", "No cache file (will be created on first scan)", "#6B7280")
                )

        except Exception as e:
            checks.append(("Config validation", "⚠", f"Skipped: {str(e)[:50]}", "#FACC15"))
            warnings += 1

    # ── 6. Optional: test tooling ─────────────────────────────────────────────
    con.print()
    for cmd, import_name, pip_name, desc in _OPTIONAL_TEST:
        present = (shutil.which(cmd) is not None) or (import_name and _can_import(import_name))
        status = "✓" if present else "—"
        color = "#4ADE80" if present else "#6B7280"
        note = desc if present else f"Optional — {pip_name}"
        checks.append((f"[dim]opt:[/dim] {cmd}", status, note, color))

    # ── 7. Optional: security tooling ────────────────────────────────────────
    # Prefer tool_health's three-state probe (ok/missing/broken) — a tool that
    # is installed but not runnable (pyre without pyre.bin on Windows, codeql
    # without the CLI binary) must be reported as broken, not silently as
    # present-and-fine or absent. Unknown tools fall back to PATH/import.
    from patchi.core.agents.tool_health import _TOOLS, check_tool  # noqa: F401

    for cmd, import_name, pip_name, desc in _OPTIONAL_SECURITY:
        if cmd in _TOOLS or cmd == "pyre":
            st = check_tool(cmd)
            if st["status"] == "ok":
                note = f"{desc} ({st['version']})"
                checks.append((f"[dim]opt:[/dim] {cmd}", "✓", note, "#4ADE80"))
            elif st["status"] == "broken":
                checks.append(
                    (f"[dim]opt:[/dim] {cmd}", "✗", f"Broken: {st['hint']}", "#FF4D6D")
                )
                errors += 1
            else:
                note = f"Optional — {pip_name}"
                checks.append((f"[dim]opt:[/dim] {cmd}", "—", note, "#6B7280"))
            continue
        present = (shutil.which(cmd) is not None) or (import_name and _can_import(import_name))
        status = "✓" if present else "—"
        color = "#4ADE80" if present else "#6B7280"
        note = desc if present else f"Optional — pip install {pip_name}"
        checks.append((f"[dim]opt:[/dim] {cmd}", status, note, color))

    # ── Render results ────────────────────────────────────────────────────────
    _render_table(checks)

    # ── Summary ───────────────────────────────────────────────────────────────
    con.print()
    if errors == 0 and warnings == 0:
        con.print(
            Panel(
                "[bold #4ADE80]All checks passed. Patchi is ready.[/bold #4ADE80]",
                border_style="#4ADE80",
                padding=(0, 1),
            )
        )
    elif errors == 0:
        con.print(
            Panel(
                f"[bold #FACC15]{warnings} warning(s). Core functionality OK.[/bold #FACC15]",
                border_style="#FACC15",
                padding=(0, 1),
            )
        )
    else:
        con.print(
            Panel(
                f"[bold #FF4D6D]{errors} error(s), {warnings} warning(s). Fix errors above.[/bold #FF4D6D]",
                border_style="#FF4D6D",
                padding=(0, 1),
            )
        )
    con.print()

# ── Helpers ────────────────────────────────────────────────────────────────────

def _can_import(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False

def _test_api_key(key_entry: dict) -> tuple[bool, str]:
    """Attempt a minimal live connection to the configured AI provider."""
    try:
        import os

        import httpx

        provider = key_entry.get("provider", "openai")
        env_var = key_entry.get("env_var", "")
        api_key = os.environ.get(env_var, "")
        nickname = key_entry.get("nickname", key_entry.get("name", provider))

        if not api_key:
            return False, "Key value is empty"

        if provider == "anthropic":
            resp = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=8.0,
            )
        else:
            base = key_entry.get(
                "base_url",
                "https://api.openai.com" if provider == "openai" else "https://openrouter.ai/api",
            )
            model = key_entry.get("model", "gpt-3.5-turbo")
            resp = httpx.post(
                f"{base.rstrip('/')}/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "hi"}],
                },
                timeout=8.0,
            )

        if resp.status_code in (200, 400):
            return True, f"{nickname} — connection OK (HTTP {resp.status_code})"
        if resp.status_code == 401:
            return False, f"{nickname} — invalid key (401 Unauthorized)"
        return False, f"{nickname} — HTTP {resp.status_code}"

    except Exception as e:
        return False, f"Connection error: {str(e)[:50]}"

def _test_ollama(model_name: str) -> tuple[bool, str]:
    """Check if Ollama is running and the model is available."""
    try:
        import httpx

        from patchi.core.constants import OLLAMA_TAGS_URL

        resp = httpx.get(OLLAMA_TAGS_URL, timeout=4.0)
        if resp.status_code != 200:
            return False, "Ollama not responding on localhost:11434"
        models = [m["name"] for m in resp.json().get("models", [])]
        if any(m.startswith(model_name.split(":")[0]) for m in models):
            return True, "Model available — Ollama running"
        return False, f"Model '{model_name}' not pulled — run: ollama pull {model_name}"
    except Exception as e:
        _log.debug("_test_ollama failed: %s", e)
        return False, "Ollama not running — start with: ollama serve"

def _render_table(checks: list[tuple[str, str, str, str]]) -> None:
    table = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
    table.add_column("Status", width=4)
    table.add_column("Check", style="bold #F2EDD6", width=28)
    table.add_column("Note", style="dim", width=55)

    for label, status, note, color in checks:
        table.add_row(
            Text(status, style=color),
            label,
            note,
        )
    con.print(table)
