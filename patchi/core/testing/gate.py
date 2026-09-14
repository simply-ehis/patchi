"""
Gate Rule — injected into every Testing/Live/Attack agent.

Before doing any work, MUST confirm:
  1. P-Check has run
  2. It returned READY_TO_SERVE with zero unresolved errors
  3. (Active tools) Target is within authorized scope — localhost or
     explicitly allowlisted hosts only.  Production hosts are never
     tested without an explicit user confirmation.
If false: do not run, request P-Check, stay idle.
Once READY_TO_SERVE confirmed: retrieve URL and begin work.
"""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

# Hosts that are always safe for automated active testing.
_LOCALHOST_VARIANTS = frozenset({
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
})


def require_ready(root: Path) -> tuple[bool, str | None, dict | None]:
    """Check gate. Returns (ready, url, status_dict)."""
    from patchi.cli.commands.check_cmd import is_ready

    ready, st = is_ready(root)
    if ready and st:
        return True, st.get("url"), st
    return False, None, st


def require_scope(url: str | None, *, allow_hosts: set[str] | None = None) -> tuple[bool, str]:
    """Check that *url* is within the authorized scope for active testing.

    Active tools (DAST, attack agents) must never fire against production
    hosts without explicit user confirmation.  This gate enforces the
    minimum: only localhost/loopback addresses are allowed by default.

    Returns (allowed, reason).
    """
    if not url:
        return False, "No target URL provided."

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    # Always allow localhost / loopback.
    if host in _LOCALHOST_VARIANTS:
        return True, "Target is localhost — within scope."

    # Allow explicit allowlist (e.g. from charter or config).
    if allow_hosts and host in allow_hosts:
        return True, f"Target '{host}' is in the explicit allowlist."

    # Everything else is blocked — the user must confirm manually.
    return False, (
        f"Target '{host}' is not a localhost address. "
        f"Active testing against non-local hosts requires explicit user "
        f"confirmation. Add '{host}' to the charter allowlist or confirm "
        f"manually via `p check --allow-host {host}`."
    )


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
