"""
`p authorize` — record who approved active testing against which host.

Active tools (nuclei/sqlmap/dalfox/ffuf/zap, DAST) send real traffic. This
command stores the approval (approver + scope + time window) that makes a
customer engagement defensible, and lists/revokes it.

Usage:
  p authorize --target https://shop.client.com --by "Jane (CTO)"
  p authorize --target shop.client.com --by Jane --scope /,/api --hours 72 --purpose "Q3 pentest"
  p authorize --list [--json]
  p authorize --revoke shop.client.com
"""

from __future__ import annotations

from pathlib import Path

from patchi.cli.console import con, print_json
from patchi.core.config import require_project_root


def run(
    target: str | None = None,
    by: str | None = None,
    scope: str | None = None,
    hours: float = 24.0,
    purpose: str = "",
    list_: bool = False,
    revoke: str | None = None,
    json_output: bool = False,
    root: Path | None = None,
) -> int:
    """Entry point for `p authorize`."""
    from patchi.core.testing import authorization as auth

    r = root or require_project_root()

    if list_:
        grants = auth.list_authorizations(r)
        if json_output:
            print_json({"grants": grants})
        elif not grants:
            con.print("[dim]No testing authorizations recorded.[/dim]")
        else:
            for g in grants:
                state = "[red]expired[/red]" if g["expired"] else "[green]valid[/green]"
                con.print(
                    f"  [bold]{g['host']}[/bold]  {state}  by {g['approved_by']}  "
                    f"[dim]scope {','.join(g.get('scope_paths', ['/']))}"
                    + (f"  purpose: {g.get('purpose', '')}" if g.get("purpose") else "")
                    + "[/dim]"
                )
        return 0

    if revoke:
        if auth.revoke(r, revoke):
            con.print(f"[green]Revoked testing authorization for {auth.normalize_host(revoke)}.[/green]")
            return 0
        con.print(f"[dim]No grant found for {auth.normalize_host(revoke)}.[/dim]")
        return 1

    if not target or not by:
        con.print("[red]Usage: p authorize --target <host> --by <approver-name>[/red]")
        con.print("[dim]Requesting tests need --target and --by. See --list / --revoke.[/dim]")
        return 2

    try:
        record = auth.grant(
            r,
            target,
            approved_by=by,
            scope_paths=[s.strip() for s in (scope or "/").split(",") if s.strip()],
            window_hours=hours,
            purpose=purpose,
        )
    except ValueError as exc:
        con.print(f"[red]Cannot record authorization: {exc}[/red]")
        return 2

    if json_output:
        print_json({"grant": record})
    else:
        scope_str = ",".join(record["scope_paths"])
        con.print(
            f"[green]Authorized active testing of {record['host']}[/green] "
            f"[dim]by {record['approved_by']}, scope {scope_str}, "
            f"{hours}h window.[/dim]"
        )
    return 0
