"""
`p explain` — Teaching mode. Explains findings in plain English.

Usage:
  p explain                  — explain all unresolved findings
  p explain <finding_id>     — explain a specific finding
  p explain --type <type>    — explain a category of findings

Teaches the developer what each issue means, why it matters, and how to fix it.
No AI required — uses pre-built knowledge base.
"""

from __future__ import annotations

from rich.panel import Panel

from patchi.cli.console import con
from patchi.core import memory as mem
from patchi.core.config import require_project_root

# ── Knowledge base ────────────────────────────────────────────────────────────

_EXPLANATIONS: dict[str, dict] = {
    "hardcoded_secret": {
        "title": "Hardcoded Secret",
        "what": "An API key, password, or token is written directly in source code.",
        "why": "Anyone with access to the code (or a public repo) can steal it. "
        "Attackers scan repos specifically for these.",
        "how": "Move the secret to an environment variable",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    "sql_injection": {
        "title": "SQL Injection",
        "what": "User input is concatenated directly into a SQL query string.",
        "why": "An attacker can inject arbitrary SQL to read, modify, or delete data. "
        "This is the #1 web vulnerability worldwide.",
        "how": "Use parameterised queries\n",
        "severity": "critical",
        "cwe": "CWE-89",
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "what": "User input is rendered as HTML without escaping.",
        "why": "An attacker can inject JavaScript that runs in other users' browsers, "
        "stealing cookies, sessions, or credentials.",
        "how": "Use your framework's auto-escaping\n",
        "severity": "high",
        "cwe": "CWE-79",
    },
    "path_traversal": {
        "title": "Path Traversal",
        "what": "User input is used to construct a file path without validation.",
        "why": "An attacker can use ../../etc/passwd to read arbitrary files on the server.",
        "how": "Validate and sanitise paths\n",
        "severity": "high",
        "cwe": "CWE-22",
    },
    "confirmed_dead": {
        "title": "Dead Code",
        "what": "This file or function is never imported or called by anything.",
        "why": "Dead code confuses developers, increases maintenance burden, "
        "and can hide security issues nobody reviews.",
        "how": "Delete it. If you're unsure, run `p scan --contract` to verify "
        "it's not part of a critical flow first.",
        "severity": "low",
        "cwe": "",
    },
    "broken_import": {
        "title": "Broken Import",
        "what": "Something tries to import this file, but the reference is broken.",
        "why": "This will cause a runtime ImportError when the code path is hit.",
        "how": "Check if the import path is correct. Fix the import statement, "
        "or delete the dead reference.",
        "severity": "medium",
        "cwe": "",
    },
    "vulnerable_dependency": {
        "title": "Vulnerable Dependency",
        "what": "A package you use has a known security vulnerability (CVE).",
        "why": "Attackers exploit known CVEs automatically. The longer you wait, "
        "the more likely you are to be targeted.",
        "how": "Update the dependency\n",
        "severity": "high",
        "cwe": "",
    },
    "missing_rate_limit": {
        "title": "Missing Rate Limiting",
        "what": "An authentication endpoint has no rate limiting.",
        "why": "Attackers can brute-force passwords or credentials "
        "by sending thousands of requests per second.",
        "how": "Add rate limiting middleware\n",
        "severity": "medium",
        "cwe": "CWE-307",
    },
    "cors_wildcard": {
        "title": "CORS Wildcard with Credentials",
        "what": "Access-Control-Allow-Origin is set to * with credentials enabled.",
        "why": "This allows any website to make authenticated requests to your API, "
        "bypassing the same-origin policy entirely.",
        "how": "Replace * with an explicit allowlist of trusted origins\n",
        "severity": "critical",
        "cwe": "CWE-942",
    },
    "explicit_any": {
        "title": "TypeScript explicit `any`",
        "what": "A variable or parameter is typed as `any`, disabling type checking.",
        "why": "TypeScript can't catch bugs in `any`-typed code. "
        "It defeats the entire purpose of using TypeScript.",
        "how": "Replace `any` with the actual type\n",
        "severity": "low",
        "cwe": "",
    },
    "unsafe_cast": {
        "title": "Unsafe Type Cast",
        "what": "A double cast `as unknown as X` bypasses TypeScript's type system.",
        "why": "This hides type mismatches that will cause runtime errors.",
        "how": "Use type guards instead\n",
        "severity": "medium",
        "cwe": "",
    },
    "parse_error": {
        "title": "Parse Error",
        "what": "The file has a syntax error and cannot be parsed.",
        "why": "This file will crash when imported or executed.",
        "how": "Check the line number in the error. Common causes\n",
        "severity": "high",
        "cwe": "",
    },
    "unprotected_sensitive_route": {
        "title": "Unprotected Sensitive Route",
        "what": "A route that handles sensitive data has no auth middleware.",
        "why": "Anyone can access this endpoint without authentication.",
        "how": "Add authentication middleware\n",
        "severity": "high",
        "cwe": "CWE-306",
    },
}

def run(
    finding_id: str | None = None,
    finding_type: str | None = None,
    root=None,
) -> None:
    """Entry point for `p explain`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    con.print()

    # Specific finding by ID
    if finding_id:
        _explain_by_id(finding_id, r)
        _ask_feedback(finding_id or finding_type or "unknown", r)
        return

    # Category filter
    if finding_type:
        _explain_by_type(finding_type)
        _ask_feedback(finding_type, r)
        return

    # Show all findings with explanations
    _explain_all(r)

def _explain_by_id(finding_id: str, root) -> None:
    """Explain a specific finding by its ID."""
    issues = mem.list_issues(root)
    for issue in issues:
        if issue.get("id") == finding_id or issue.get("type") == finding_id:
            _render_explanation(issue.get("type", "unknown"), issue)
            return
    con.print(f"[yellow]Finding {finding_id!r} not found in known issues.[/yellow]")
    con.print("[dim]Run `p explain` to see all findings with explanations.[/dim]")

def _explain_by_type(finding_type: str) -> None:
    """Explain a category of findings."""
    key = finding_type.lower().replace("-", "_").replace(" ", "_")
    if key in _EXPLANATIONS:
        _render_explanation(key, {})
    else:
        con.print(f"[yellow]No explanation available for '{finding_type}'.[/yellow]")
        con.print("[dim]Available types:[/dim]")
        for k in sorted(_EXPLANATIONS.keys()):
            con.print(f"  [dim]  {k}[/dim]")

def _explain_all(root) -> None:
    """Explain all unresolved findings."""
    issues = mem.list_issues(root)

    if not issues:
        con.print("[#4ADE80]✓[/#4ADE80] No findings to explain. Run `p scan` first.")
        return

    con.print("[bold #F2EDD6]Finding Explanations[/bold #F2EDD6]")
    con.print("[dim]Each issue explained in plain English — what, why, and how to fix.[/dim]")
    con.print()

    explained = 0
    for issue in issues:
        ftype = issue.get("type", "unknown")
        if ftype in _EXPLANATIONS:
            _render_explanation(ftype, issue)
            explained += 1

    if explained == 0:
        con.print("[dim]No explanations available for the current findings.[/dim]")
        con.print("[dim]This is a knowledge gap — contributions welcome.[/dim]")

    con.print()
    con.print(f"[dim]{explained}/{len(issues)} findings explained.[/dim]")

def _render_explanation(finding_type: str, issue: dict) -> None:
    """Render a single finding explanation."""
    info = _EXPLANATIONS.get(finding_type)
    if not info:
        con.print(f"[dim]No explanation for '{finding_type}'.[/dim]")
        return

    sev = info.get("severity", "info")
    sev_colors = {
        "critical": "#FF4D6D",
        "high": "#FF8C42",
        "medium": "#FACC15",
        "low": "#4ADE80",
        "info": "#B8A898",
    }
    sev_color = sev_colors.get(sev, "#B8A898")

    file_loc = ""
    if issue.get("file"):
        line = issue.get("line", 0)
        file_loc = f"  [dim]{issue['file']}{f':{line}' if line else ''}[/dim]\n"

    cwe_tag = f"  [dim]({info['cwe']})[/dim]" if info.get("cwe") else ""

    panel_content = (
        f"[bold]What:[/bold]  {info['what']}\n\n{info['how']}"
    )

    con.print(
        Panel(
            file_loc + panel_content,
            title=f"[bold {sev_color}] {info['title']} [/bold {sev_color}]{cwe_tag}",
            border_style=sev_color,
            padding=(0, 1),
        )
    )
    con.print()

def _ask_feedback(finding_type: str, root) -> None:
    """Ask if the explanation was helpful and record the answer (WIRE-06 / M-03)."""
    import sys

    if not sys.stdin.isatty():
        return  # Skip in CI / non-interactive mode
    try:
        from rich.prompt import Confirm, Prompt

        from patchi.core.brain.learning import record_acceptance, record_rejection

        helpful = Confirm.ask("[dim]Was this explanation helpful?[/dim]", default=True)
        if helpful:
            record_acceptance(finding_type, "explain_cmd", root)
        else:
            correction = Prompt.ask(
                "[dim]What was wrong or missing? (Enter to skip)[/dim]",
                default="",
            )
            record_rejection(finding_type, "explain_cmd", root)
            if correction.strip():
                # Persist the correction so future AI calls can use it
                try:
                    corrections_path = root / ".patchi" / "memory" / "explain_corrections.json"
                    import json

                    existing = []
                    if corrections_path.exists():
                        existing = json.loads(corrections_path.read_text(encoding="utf-8"))
                    existing.append({"type": finding_type, "correction": correction.strip()})
                    corrections_path.parent.mkdir(parents=True, exist_ok=True)
                    corrections_path.write_text(
                        json.dumps(existing[-50:], indent=2), encoding="utf-8"
                    )
                except Exception as e:
                    con.print(f"[dim]Could not save correction: {e}[/dim]")
    except Exception as e:
        con.print(f"[dim]Feedback processing error: {e}[/dim]")
