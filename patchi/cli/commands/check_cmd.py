"""
P-Check Agent — sole job to get app into runnable, testable state.

Spec:
  1. Install all dependencies
  2. Run formatting/lint checks
  3. Run other required setup (env files, codegen, config validation)
  4. Attempt to build and start the app as local dev server (localhost)

When everything succeeds: output READY_TO_SERVE with exact local dev server URL and port. Stop.
When something fails: flag what failed + exact error + what is needed, escalate to Brain, wait for fix, re-run from
step 1. Never READY_TO_SERVE while blocking error remains.
Hard rule: No other agent may treat app as usable until READY_TO_SERVE.

Gate file: .patchi/p_check_status.json {status, url, port, timestamp, error}
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core.config import require_project_root

_STATUS_FILE = ".patchi/p_check_status.json"


def _write_status(
    root: Path,
    status: str,
    url: str | None = None,
    port: int | None = None,
    error: str | None = None,
    domain: str | None = None,
) -> None:
    p = root / _STATUS_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "status": status,
        "url": url,
        "port": port,
        "error": error,
        "domain": domain,
        "timestamp": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(p)


def _read_status(root: Path) -> dict | None:
    p = root / _STATUS_FILE
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _url_reachable(url: str, timeout: float = 3.0) -> tuple[bool, str]:
    """Quick liveness probe for the P-Check URL (§7: re-validate at check time).

    Any HTTP response (even 404/500) proves the server is bound; only
    connection-level failures mean "not serving".
    """
    import urllib.error
    import urllib.request

    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout):
            return True, ""
    except urllib.error.HTTPError:
        return True, ""  # server answered — bound and serving
    except Exception as e:  # noqa: BLE001 — connection refused/timeout/DNS
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout):
                return True, ""
        except urllib.error.HTTPError:
            return True, ""
        except Exception as e2:  # noqa: BLE001
            return False, f"{type(e2).__name__}: {e2}"
        return False, f"{type(e).__name__}: {e}"


def is_ready(root: Path) -> tuple[bool, dict | None]:
    """Gate Rule helper: returns (ready, status_dict)."""
    st = _read_status(root)
    if not st:
        return False, None
    if st.get("status") != "READY_TO_SERVE":
        return False, st
    if not st.get("url"):
        return False, st
    # §7: a stale READY_TO_SERVE (server died since `p check`) must not pass
    # the gate. Re-validate the URL is actually bound right now.
    ok, err = _url_reachable(st["url"])
    if not ok:
        stale = dict(st)
        stale["error"] = (
            f"READY_TO_SERVE is stale — {st['url']} unreachable ({err}). "
            "Re-run `p check` to rebuild and re-serve the app."
        )
        return False, stale
    return True, st


# Finding types p check --fix may auto-repair (its lane: type/deps/build/format/install).
# Everything else (incl. all security findings) is reported for the Brain, never touched.
_FIXABLE_TYPES = {"missing_env", "format_error"}


def _apply_domain_fixes(r: Path, blocking: list) -> list[str]:
    """Attempt safe auto-fixes for in-lane findings. Returns human-readable actions taken."""
    import shutil
    import subprocess

    actions: list[str] = []
    for f in blocking:
        ftype = getattr(f, "type", "") or ""
        if ftype == "missing_env":
            src, dst = r / ".env.example", r / ".env"
            try:
                if src.exists() and not dst.exists():
                    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
                    actions.append("copied .env.example → .env (fill values before run)")
            except OSError:
                pass
        elif ftype == "format_error":
            if shutil.which("ruff") and (r / "pyproject.toml").exists():
                try:
                    proc = subprocess.run(
                        ["ruff", "format", "."],
                        capture_output=True,
                        text=True,
                        timeout=60,
                        cwd=str(r),
                    )
                    if proc.returncode == 0:
                        actions.append("ran ruff format .")
                except Exception as _exc:
                    logging.getLogger("patchi").debug("suppressed: %s", _exc)
    return actions


def _run_side_agents(r: Path, brain: dict, config: dict):
    from patchi.core.agents.base import AgentInput
    from patchi.core.agents.base import list_agents as la

    agents = [a for a in la() if a.name in ("InstallAgent", "BuildAgent", "FormatAgent")]
    findings: list = []
    blocking: list = []
    for cls in agents:
        res = cls().run(AgentInput(root=r, scope=[], brain=brain, config=config, extra={}))
        findings.extend(res.findings)
        for f in res.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in ("high", "critical"):
                blocking.append(f)
    return findings, blocking


def run(fix: bool = False, json_output: bool = False, root: Path | None = None) -> None:
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.agents.base import discover_agent_modules

    discover_agent_modules()
    import patchi.core.agents.side.build_agent  # noqa: F401
    import patchi.core.agents.side.format_agent  # noqa: F401
    import patchi.core.agents.side.install_agent  # noqa: F401

    try:
        from patchi.core import config as cfg
        from patchi.core import memory as mem

        brain = mem.get_brain(r)
        config = cfg.load(r)
    except Exception:
        brain, config = {}, {}

    # Step 1-3: run side agents
    findings, blocking = _run_side_agents(r, brain, config)

    # --fix: repair in-lane findings once, then re-run from step 1
    if fix and blocking:
        lane = [f for f in blocking if (getattr(f, "type", "") or "") in _FIXABLE_TYPES]
        if lane:
            actions = _apply_domain_fixes(r, lane)
            if actions:
                for a in actions:
                    con.print(f"[dim]--fix: {a}[/dim]")
                findings, blocking = _run_side_agents(r, brain, config)

    # Step 3 extra: env file check (missing .env but .env.example exists)
    try:
        if (r / ".env.example").exists() and not (r / ".env").exists():
            from patchi.core.agents.base import Severity, make_finding

            findings.append(
                make_finding(
                    severity=Severity.HIGH,
                    file=".env",
                    line_start=0,
                    title="Missing .env (have .env.example)",
                    description="Copy .env.example to .env and fill values before app can run",
                    finding_type="missing_env",
                )
            )
            blocking.append(findings[-1])
    except Exception as _exc:
        logging.getLogger("patchi").debug("suppressed: %s", _exc)

    if blocking:
        # Escalate to Brain
        msg = (
        f"P-Check BLOCKED: {len(blocking)} blocking error(s) in"
        f" {', '.join({f.file or 'unknown' for f in blocking})}"
        )
        con.print()
        con.print(
            Panel(
                f"[red]{msg}[/red]\n" + "\n".join(f"  • {f.file}:{f.line} {f.message[:100]}" for f in blocking[:5]),
                title="P-Check — BLOCKED",
                border_style="#FF4D6D",
            )
        )
        con.print(f"[dim]Escalating to Brain (orchestrator) — domain: {[f.type for f in blocking[:3]]}[/dim]")
        _write_status(r, "BLOCKED", error=msg, domain=",".join({f.type for f in blocking}))
        try:
            from patchi.core import memory as mem

            mem.save_scan_result("PCheck", {"status": "BLOCKED", "findings": [f.to_dict() for f in findings]}, r)
            # also save as issue for brain
            for f in blocking[:5]:
                mem.save_issue(
                    {
                        "type": f.type,
                        "file": f.file,
                        "line": f.line,
                        "message": f.message,
                        "source": "PCheck",
                    },
                    r,
                )
        except Exception as _exc:
            logging.getLogger("patchi").debug("suppressed: %s", _exc)
        con.print(
            con.print(
                "[yellow]P-Check: fix blocking errors (or run p check --fix if in domain) then re-run `p check` from"
                " step 1. Never READY_TO_SERVE while blocked.[/yellow]"
            )
        )
        con.print()
        if json_output:
            con.print(json.dumps({"status": "BLOCKED", "blocking": [f.to_dict() for f in blocking]}, indent=2))
        return

    # Step 4: attempt to build and start app as local dev server
    url: str | None = None
    port: int | None = None
    try:
        from patchi.core.testing.app_launcher import ensure_running

        url = ensure_running(r, config, {})
        if url:
            # parse port
            try:
                port = int(url.rsplit(":", 1)[-1].split("/")[0])
            except Exception:
                port = None
    except Exception as exc:  # noqa: BLE001
        con.print(f"[red]P-Check start failed: {exc}[/red]")
        _write_status(r, "BLOCKED", error=str(exc), domain="app_start")
        return

    if not url:
        msg = "P-Check could not start app — no start command detected or port health check failed"
        con.print()
        con.print(
            Panel(
                f"[yellow]{msg}[/yellow]\n[dim]Check app_launcher logs at .patchi/launcher/app.log[/dim]",
                title="P-Check — BLOCKED (no URL)",
                border_style="#FF8C42",
            )
        )
        con.print()
        _write_status(r, "BLOCKED", error=msg, domain="app_start")
        return

    # Success
    con.print()
    con.print(
        Panel(
            f"[bold #4ADE80]READY_TO_SERVE[/bold #4ADE80]\nLocal dev server URL: [bold]{url}[/bold] port {port}\n"
            f"[dim]P-Check complete — app is runnable, testable. No other agent may proceed until this was"
            f" emitted.[/dim]",
            border_style="#4ADE80",
        )
    )
    con.print()
    _write_status(r, "READY_TO_SERVE", url=url, port=port)
    try:
        from patchi.core import memory as mem

        mem.save_scan_result(
            "PCheck",
            {
                "status": "READY_TO_SERVE",
                "url": url,
                "port": port,
                "findings": [f.to_dict() for f in findings],
            },
            r,
        )
    except Exception as _exc:
        logging.getLogger("patchi").debug("suppressed: %s", _exc)
    if json_output:
        con.print(json.dumps({"status": "READY_TO_SERVE", "url": url, "port": port}, indent=2))
