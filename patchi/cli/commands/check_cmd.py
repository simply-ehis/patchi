"""
P-Check Agent — sole job to get app into runnable, testable state.

Spec:
  1. Install all dependencies
  2. Run formatting/lint checks
  3. Run other required setup (env files, codegen, config validation)
  4. Attempt to build and start the app as local dev server (localhost)

When everything succeeds: output READY_TO_SERVE with exact local dev server URL and port. Stop.
When something fails: flag what failed + exact error + what is needed, escalate to Brain, wait for fix, re-run from step 1. Never READY_TO_SERVE while blocking error remains.
Hard rule: No other agent may treat app as usable until READY_TO_SERVE.

Gate file: .patchi/p_check_status.json {status, url, port, timestamp, error}
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core.config import require_project_root

_STATUS_FILE = ".patchi/p_check_status.json"


def _write_status(root: Path, status: str, url: str | None = None, port: int | None = None, error: str | None = None, domain: str | None = None) -> None:
    p = root / _STATUS_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {"status": status, "url": url, "port": port, "error": error, "domain": domain, "timestamp": time.time(), "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
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


def is_ready(root: Path) -> tuple[bool, dict | None]:
    """Gate Rule helper: returns (ready, status_dict)."""
    st = _read_status(root)
    if not st:
        return False, None
    if st.get("status") != "READY_TO_SERVE":
        return False, st
    # optional TTL: 1 hour? For now no expiry, but check url still reachable?
    if not st.get("url"):
        return False, st
    # check timestamp within 1 hour or still running?
    return True, st


def run(fix: bool = False, json_output: bool = False, root: Path | None = None) -> None:  # noqa: ARG001
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core.agents.base import AgentInput, discover_agent_modules

    discover_agent_modules()
    import patchi.core.agents.side.build_agent  # noqa: F401
    import patchi.core.agents.side.format_agent  # noqa: F401
    import patchi.core.agents.side.install_agent  # noqa: F401
    from patchi.core.agents.base import list_agents as la

    # Side agents for steps 1-2
    agents = [a for a in la() if a.name in ("InstallAgent", "BuildAgent", "FormatAgent")]
    try:
        from patchi.core import config as cfg
        from patchi.core import memory as mem

        brain = mem.get_brain(r)
        config = cfg.load(r)
    except Exception:
        brain, config = {}, {}

    # Step 1-3: run side agents
    findings: list = []
    blocking: list = []
    for cls in agents:
        res = cls().run(AgentInput(root=r, scope=[], brain=brain, config=config, extra={}))
        findings.extend(res.findings)
        for f in res.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in ("high", "critical"):
                blocking.append(f)

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
    except Exception:
        pass

    if blocking:
        # Escalate to Brain
        msg = f"P-Check BLOCKED: {len(blocking)} blocking error(s) in {', '.join({f.file or 'unknown' for f in blocking})}"
        con.print()
        con.print(Panel(f"[red]{msg}[/red]\n" + "\n".join(f"  • {f.file}:{f.line} {f.message[:100]}" for f in blocking[:5]), title="P-Check — BLOCKED", border_style="#FF4D6D"))
        con.print(f"[dim]Escalating to Brain (orchestrator) — domain: {[f.type for f in blocking[:3]]}[/dim]")
        _write_status(r, "BLOCKED", error=msg, domain=",".join({f.type for f in blocking}))
        try:
            from patchi.core import memory as mem

            mem.save_scan_result("PCheck", {"status": "BLOCKED", "findings": [f.to_dict() for f in findings]}, r)
            # also save as issue for brain
            for f in blocking[:5]:
                mem.save_issue({"type": f.type, "file": f.file, "line": f.line, "message": f.message, "source": "PCheck"}, r)
        except Exception:
            pass
        con.print("[yellow]P-Check: fix blocking errors (or run p check --fix if in domain) then re-run `p check` from step 1. Never READY_TO_SERVE while blocked.[/yellow]")
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
        con.print(Panel(f"[yellow]{msg}[/yellow]\n[dim]Check app_launcher logs at .patchi/launcher/app.log[/dim]", title="P-Check — BLOCKED (no URL)", border_style="#FF8C42"))
        con.print()
        _write_status(r, "BLOCKED", error=msg, domain="app_start")
        return

    # Success
    con.print()
    con.print(Panel(f"[bold #4ADE80]READY_TO_SERVE[/bold #4ADE80]\nLocal dev server URL: [bold]{url}[/bold] port {port}\n[dim]P-Check complete — app is runnable, testable. No other agent may proceed until this was emitted.[/dim]", border_style="#4ADE80"))
    con.print()
    _write_status(r, "READY_TO_SERVE", url=url, port=port)
    try:
        from patchi.core import memory as mem

        mem.save_scan_result("PCheck", {"status": "READY_TO_SERVE", "url": url, "port": port, "findings": [f.to_dict() for f in findings]}, r)
    except Exception:
        pass
    if json_output:
        con.print(json.dumps({"status": "READY_TO_SERVE", "url": url, "port": port}, indent=2))
