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


def require_scope(
    url: str | None,
    *,
    allow_hosts: set[str] | None = None,
    require_explicit: bool = False,
) -> tuple[bool, str]:
    """Check that *url* is within the authorized scope for active testing.

    Active tools (DAST, attack agents) must never fire against production
    hosts without explicit user confirmation.  This gate enforces the
    minimum: only hosts listed in an explicit allowlist (charter or
    ``--target`` flag) are allowed when *require_explicit* is True.

    Returns (allowed, reason).
    """
    if not url:
        return False, "No target URL provided."

    # When require_explicit is set (DAST charter gate), block *all*
    # active tools if no explicit targets are defined — including
    # localhost.  The user must declare intent via the charter or
    # the --target CLI flag.
    if require_explicit and not allow_hosts:
        return False, (
            "No explicit targets defined. Active testing requires at least "
            "one target listed in the project charter or passed via --target. "
            "Add a target to your charter or run with --target <url>."
        )

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    # Allow localhost / loopback.
    if host in _LOCALHOST_VARIANTS:
        return True, "Target is localhost — within scope."

    # Allow explicit allowlist (from charter or --target flag).
    if host in allow_hosts:
        return True, f"Target '{host}' is in the explicit allowlist."

    # Everything else is blocked — the user must confirm manually.
    return False, (
        f"Target '{host}' is not in the explicit allowlist. "
        f"Active testing against non-listed hosts requires explicit user "
        f"confirmation. Add '{host}' to the charter or confirm "
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
