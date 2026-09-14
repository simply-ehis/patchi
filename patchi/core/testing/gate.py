"""
Gate Rule — injected into every Testing/Live/Attack agent.

Before doing any work, MUST confirm:
  1. P-Check has run
  2. It returned READY_TO_SERVE with zero unresolved errors
If false: do not run, request P-Check, stay idle.
Once READY_TO_SERVE confirmed: retrieve URL and begin work.
"""

from __future__ import annotations

from pathlib import Path


def require_ready(root: Path) -> tuple[bool, str | None, dict | None]:
    """Check gate. Returns (ready, url, status_dict)."""
    from patchi.cli.commands.check_cmd import is_ready

    ready, st = is_ready(root)
    if ready and st:
        return True, st.get("url"), st
    return False, None, st


def gate_message(status: dict | None) -> str:
    if not status:
        return "P-Check has not run — request `p check` and wait for READY_TO_SERVE. Do not run/test/attack anything."
    if status.get("status") != "READY_TO_SERVE":
        return (
        f"P-Check is {status.get('status')} ({status.get('error', '')}) — request `p check` re-run and let it"
        f" escalate to Brain. Stay idle."
        )
    # READY_TO_SERVE but the re-validation failed (is_ready attaches an error):
    # saying "confirmed" here would green-light agents against a dead server.
    if status.get("error"):
        return f"READY_TO_SERVE is STALE — {status['error']}"
    return "READY_TO_SERVE confirmed"
