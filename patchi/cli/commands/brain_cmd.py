"""
`p brain` — Transform brain knowledge into a readable markdown document.

Generates `.patchi/BRAIN.md` — a plain English explanation of everything
Patchi knows about your project. Auto-updates after every scan.

Usage:
  p brain              — generate/update BRAIN.md
  p brain --show       — print BRAIN.md to terminal
  p brain --force      — force regeneration even if no new scan
"""

from __future__ import annotations

import time
from pathlib import Path

from patchi.cli.console import con
from patchi.core.config import require_project_root


def run(
    show: bool = False,
    force: bool = False,
    root: Path | None = None,
) -> None:
    """Entry point for `p brain`."""
    try:
        r = root or require_project_root()
    except RuntimeError as e:
        con.print(f"[red]{e}[/red]")
        return

    from patchi.core import memory as mem

    brain = mem.get_brain(r)
    if not brain or not brain.get("file_count"):
        con.print("[yellow]No brain data found. Run 'p scan' first.[/yellow]")
        return

    brain_md = _generate_brain_md(brain, r)
    md_path = r / ".patchi" / "BRAIN.md"
    md_path.parent.mkdir(parents=True, exist_ok=True)

    # Check if we need to update
    if md_path.exists() and not force:
        existing = md_path.read_text(encoding="utf-8")
        old_scan = _extract_scan_time(existing)
        new_scan = brain.get("last_scan", "")
        if old_scan == new_scan and not force:
            if show:
                con.print(existing)
            else:
                con.print(
                    "[dim]BRAIN.md is up to date (no new scan). Use --force to regenerate.[/dim]"
                )
            return

    md_path.write_text(brain_md, encoding="utf-8")

    if show:
        con.print(brain_md)
    else:
        con.print(
            "[bold #4ADE80]✓[/bold #4ADE80] Brain knowledge written to [dim].patchi/BRAIN.md[/dim]"
        )
        con.print(f"  [dim]{len(brain_md.splitlines())} lines, {len(brain_md)} bytes[/dim]")

def _extract_scan_time(md_content: str) -> str:
    """Extract scan timestamp from existing BRAIN.md."""
    for line in md_content.splitlines():
        if line.startswith("<!-- scan_time:") and line.endswith("-->"):
            return line.split(":", 1)[1].strip().removesuffix("-->").strip()
    return ""

def _generate_brain_md(brain: dict, root: Path) -> str:
    """Generate a plain English markdown document from brain data."""
    lines = []
    scan_time = brain.get("last_scan", "unknown")
    lines.append(f"<!-- scan_time: {scan_time} -->")
    lines.append("")
    lines.append("# What Patchi Knows About This Project")
    lines.append("")
    lines.append("*This document updates automatically every time you run a scan.*")
    lines.append(f"*Last updated: {time.strftime('%B %d, %Y at %H:%M')}*")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ── What is this project? ─────────────────────────────────────────────────
    file_count = brain.get("file_count", 0)
    route_count = brain.get("route_count", 0)
    framework = brain.get("framework", "Unknown")
    languages = brain.get("languages", {})

    lines.append("## What Is This Project?")
    lines.append("")

    # Show AI-generated purpose if available
    project_purpose = brain.get("project_purpose", "")
    if project_purpose:
        lines.append(project_purpose)
        lines.append("")

    # Build a natural language description
    lang_parts = []
    for lang, count in sorted(languages.items(), key=lambda x: -x[1]):
        if lang.lower() == "python":
            lang_parts.append(f"{count} Python files")
        elif lang.lower() == "javascript":
            lang_parts.append(f"{count} JavaScript files")
        elif lang.lower() == "typescript":
            lang_parts.append(f"{count} TypeScript files")
        elif lang.lower() == "html":
            lang_parts.append(f"{count} HTML files")
        elif lang.lower() == "css":
            lang_parts.append(f"{count} CSS files")
        elif lang.lower() == "bash":
            lang_parts.append(f"{count} shell scripts")
        else:
            lang_parts.append(f"{count} {lang} files")

    lang_str = ", ".join(lang_parts)
    domain = brain.get("project_domain", "")
    domain_str = f" ({domain} domain)" if domain else ""
    lines.append(
        f"This is a **{framework}** application with **{file_count} files**{domain_str} "
        f"({lang_str})."
    )
    lines.append("")

    if route_count > 0:
        lines.append(
            f"It has **{route_count} routes or entry points** — "
            f"these are the places where your app handles requests "
            f"or starts executing code."
        )
        lines.append("")

    # ── Health Score (plain English) ──────────────────────────────────────────
    health = brain.get("health_score", {})
    total = health.get("total", 0)
    components = health.get("components", {})

    lines.append("## How Healthy Is This Project?")
    lines.append("")

    if total >= 90:
        health_desc = "Excellent — this project is in great shape."
    elif total >= 70:
        health_desc = "Good — mostly healthy with some areas to improve."
    elif total >= 50:
        health_desc = "Fair — there are several issues that need attention."
    elif total >= 30:
        health_desc = "Poor — significant problems that should be addressed soon."
    else:
        health_desc = "Critical — this project needs immediate work."

    lines.append(f"**Overall score: {total} out of 100** — {health_desc}")
    lines.append("")

    if components:
        lines.append("Here's the breakdown:")
        lines.append("")
        for comp, score in components.items():
            comp_name = comp.replace("_", " ").title()
            if score >= 90:
                comp_desc = "excellent"
            elif score >= 70:
                comp_desc = "good"
            elif score >= 50:
                comp_desc = "needs work"
            elif score >= 30:
                comp_desc = "poor"
            else:
                comp_desc = "critical"
            lines.append(f"- **{comp_name}**: {score:.0f}/100 ({comp_desc})")
        lines.append("")

    # ── What's in the codebase ────────────────────────────────────────────────
    dead_files = brain.get("dead_files", [])
    circular = brain.get("circular_deps", [])

    if dead_files or circular:
        lines.append("## What Needs Attention")
        lines.append("")

        if dead_files:
            lines.append(f"### Dead Code ({len(dead_files)} files)")
            lines.append("")
            lines.append(
                "These files are not imported by anything else. "
                "They might be leftover code that can be safely removed:"
            )
            lines.append("")
            for f in dead_files[:10]:
                lines.append(f"- `{f}`")
            if len(dead_files) > 10:
                lines.append(f"- ...and {len(dead_files) - 10} more")
            lines.append("")

        if circular:
            lines.append(f"### Circular Dependencies ({len(circular)} chains)")
            lines.append("")
            lines.append(
                "These files depend on each other in a loop. "
                "This can cause problems and should be restructured:"
            )
            lines.append("")
            for chain in circular[:3]:
                if isinstance(chain, dict):
                    files = chain.get("files", chain.get("path", []))
                else:
                    files = chain if isinstance(chain, list) else [str(chain)]
                if files:
                    lines.append("- " + " → ".join(f"`{f}`" for f in files))
            lines.append("")

    # ── App Contract ──────────────────────────────────────────────────────────
    inferred = brain.get("inferred_flows", [])
    confirmed = brain.get("confirmed_flows", [])

    if inferred:
        lines.append("## How Your App Works")
        lines.append("")
        lines.append("Patchi has identified these important flows in your app:")
        lines.append("")

        for flow in inferred[:8]:
            if isinstance(flow, dict):
                name = flow.get("name", flow.get("description", "Unknown"))
                lines.append(f"- **{name}**")
            else:
                lines.append(f"- **{flow}**")

        if confirmed:
            lines.append("")
            lines.append(f"**{len(confirmed)}** of these have been confirmed as real flows.")
        lines.append("")

    # ── Where things are ──────────────────────────────────────────────────────
    import_graph = brain.get("import_graph", {})
    nodes = import_graph.get("nodes", [])

    if nodes:
        lines.append("## Where Things Are")
        lines.append("")
        lines.append("The main parts of this project:")
        lines.append("")

        # Group by directory
        modules = {}
        for node in nodes:
            parts = node.split("/")
            if len(parts) >= 2:
                mod = parts[0] + "/" + parts[1]
            else:
                mod = parts[0]
            modules.setdefault(mod, []).append(node)

        # Show top modules
        for mod, files in sorted(modules.items(), key=lambda x: -len(x[1]))[:8]:
            if len(files) > 1:
                lines.append(f"- **`{mod}/`** — {len(files)} files")
            else:
                lines.append(f"- **`{mod}`** — 1 file")
        lines.append("")

    # ── Security Status ───────────────────────────────────────────────────────
    lines.append("## Security")
    lines.append("")
    lines.append("Run `p security` to check for security problems.")
    lines.append("Run `p security report` for a detailed report with risk scores.")
    lines.append("")

    # ── Quick Actions ─────────────────────────────────────────────────────────
    lines.append("## What You Can Do Next")
    lines.append("")
    lines.append("| If you want to... | Run this |")
    lines.append("|-------------------|----------|")
    lines.append("| Check overall health | `p status` |")
    lines.append("| Find security issues | `p security` |")
    lines.append("| Get a detailed report | `p security report` |")
    lines.append("| Fix problems automatically | `p fix` |")
    lines.append("| Run tests | `p test` |")
    lines.append("| See what breaks if you change a file | `p blast <file>` |")
    lines.append("| Ask questions about your code | `p chat` |")
    lines.append("| Understand a specific issue | `p explain` |")
    lines.append("| Monitor in production | `p hosted init` |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        f"*This document was generated from a scan that took "
        f"{brain.get('duration', 0):.1f} seconds.*"
    )
    lines.append("")

    return "\n".join(lines)
