"""`p docs` — Generate a project architecture document.

Tier 1: pure rendering from Brain data, works with zero AI configured.
Tier 2: scoped AI narration (future, requires harness).

Usage:
    p docs                  # Generate docs to docs/ARCHITECTURE.md
    p docs --output FILE    # Write to a specific file
    p docs --stdout         # Print to stdout instead of file
    p docs --regen          # Force regeneration even if docs look fresh
    p docs --auto           # Auto-regenerate when docs are stale
    p docs --check          # Compare current state against stored metadata
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

from patchi.cli.framework import Arg

_log = logging.getLogger(__name__)

ARGS = (
    Arg("--output", help="Output file path", default=None),
    Arg("--stdout", help="Print to stdout instead of writing a file", action="store_true"),
    Arg("--regen", action="store_true", help="Force regeneration even if docs look fresh"),
    Arg("--auto", action="store_true", help="Auto-regenerate when docs are stale (skip if fresh)"),
    Arg("--check", action="store_true", help="Compare current state against stored doc metadata"),
)


def run(args: object) -> None:
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    root = Path(getattr(args, "project_root", "."))
    output_path = getattr(args, "output", None)
    to_stdout = getattr(args, "stdout", False)
    regen = getattr(args, "regen", False)
    auto = getattr(args, "auto", False)
    check = getattr(args, "check", False)

    console.print(Panel("[bold]Patchi — Project Architecture Doc[/bold]", style="blue"))

    # Handle --check: compare current state vs stored metadata.
    if check:
        _run_check(root, console)
        return

    # Determine the docs directory for freshness check.
    docs_dir = root / "docs"
    if not output_path:
        from patchi.core.brain.docs_generator import _check_docs_freshness

        report = _check_docs_freshness(docs_dir, root)

        if report.fresh and not regen:
            if auto:
                console.print("[green]Docs are fresh — skipping regeneration.[/green]")
                return
            console.print("[yellow]Docs appear up-to-date.[/yellow]")
            console.print(
                "  Source files newer than doc: none detected.\n"
                "  Use [bold]--regen[/bold] to force regeneration."
            )
            return

        if not report.fresh:
            n = len(report.stale_files)
            console.print(f"[yellow]Docs are stale — {n} source file(s) newer than doc.[/yellow]")
            if not auto and not regen:
                console.print(
                    "  Run [bold]p docs --regen[/bold] to update, or "
                    "[bold]p docs --auto[/bold] to auto-regenerate on staleness."
                )

    # Build brain data from a lightweight scan.
    brain_data = _build_brain_data(root, console)

    # Check if AI is available.
    ai_available = _check_ai()

    # Generate the doc.
    from patchi.cli.markdown_writer import write_markdown
    from patchi.core.brain.docs_generator import (
        generate_docs,
        generate_sections,
        project_name,
    )

    project_name_str = project_name(root, brain_data)
    doc = generate_docs(root, brain_data=brain_data, ai_available=ai_available)

    # Output.
    if to_stdout:
        sys.stdout.write(doc)
        return

    if not output_path:
        # Default: docs/ARCHITECTURE.md in the project root.
        docs_dir.mkdir(exist_ok=True)
        output_path = str(docs_dir / "ARCHITECTURE.md")

    out = Path(output_path)
    sections = generate_sections(root, brain_data=brain_data, ai_available=ai_available)
    write_markdown(out, f"{project_name_str} — Architecture", sections)
    console.print(f"\n[green]✓[/green] Architecture doc written to [bold]{out}[/bold]")
    console.print("  Sections: overview, tree, routes, abstractions, dependencies, capabilities, functionality")

    # Write .patchi-meta.json alongside the doc (only for default docs/ output).
    if not output_path or not to_stdout:
        from patchi.core.brain.docs_generator import _build_doc_metadata

        meta = _build_doc_metadata(root, brain_data)
        meta_path = docs_dir / ".patchi-meta.json"
        meta_path.parent.mkdir(exist_ok=True)
        meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        console.print(f"  [dim]Metadata written to {meta_path}[/dim]")

    # ── Tier 2 knowledge docs ─────────────────────────────────────────────────
    try:
        from patchi.core.brain.knowledge_doc_generator import generate_knowledge_docs

        console.print("  [dim]Generating Tier 2 knowledge docs...[/dim]")
        knowledge_docs = generate_knowledge_docs(root, brain_data)
        for filename, content in knowledge_docs.items():
            kpath = docs_dir / filename
            kpath.write_text(content, encoding="utf-8")
            console.print(f"  [dim]Wrote {kpath}[/dim]")
    except Exception as exc:
        _log.debug("Knowledge doc generation failed: %s", exc)

    # ── Gap detection ────────────────────────────────────────────────────────
    try:
        from patchi.core.brain.doc_gaps import detect_doc_gaps

        gaps = detect_doc_gaps(root, brain_data)
        if gaps:
            from rich.table import Table

            table = Table(title="Documentation Gaps", show_header=True, header_style="bold yellow")
            table.add_column("Status", style="bold")
            table.add_column("Area")
            table.add_column("Expected Doc")
            table.add_column("Suggestion")
            for gap in gaps:
                status_style = {"missing": "red", "partial": "yellow", "stale": "dim"}.get(gap.status, "")
                table.add_row(
                    f"[{status_style}]{gap.status.upper()}[/{status_style}]",
                    gap.area,
                    gap.expected_doc,
                    gap.suggestion,
                )
            console.print()
            console.print(table)
    except Exception as exc:
        _log.debug("Gap detection failed: %s", exc)


def _build_brain_data(root: Path, console: object) -> dict:
    """Build brain data from a lightweight scan pass."""
    brain: dict = {}

    try:
        from patchi.core.brain.scanner import run_scanners

        console.print("  [dim]Scanning project structure...[/dim]")
        scan_result = run_scanners(root)
        brain.update(scan_result)
    except Exception as e:
        _log.debug("Scan pass failed: %s", e)
        console.print(f"  [yellow]⚠ Scan pass failed: {e}[/yellow]")

    # Import graph for Mermaid diagrams.
    try:
        from patchi.core.brain.import_graph import build_import_graph

        console.print("  [dim]Building import graph...[/dim]")
        graph = build_import_graph(root)
        brain["import_graph"] = graph
    except Exception as e:
        _log.debug("Import graph build failed: %s", e)

    # Symbol graph for abstractions.
    try:
        from patchi.core.brain.symbol_graph import SymbolGraph

        sg = SymbolGraph(root)
        count = sg.ensure_built()
        if count > 0:
            brain["symbols"] = [s.to_dict() for s in sg.get_all_symbols()]
            brain["symbol_edges"] = sg.export_json().get("edges", [])
        sg.close()
    except Exception as e:
        _log.debug("Symbol graph build failed: %s", e)

    return brain


def _check_ai() -> bool:
    """Check if an AI provider is configured."""
    try:
        from patchi.core.config import load_config

        config = load_config()
        ai = config.get("ai", {})
        return bool(ai.get("provider") and ai.get("api_key"))
    except Exception:
        return False


def _run_check(root: Path, console: object) -> None:
    """`p docs --check` — compare current project state against the stored doc.

    Three signals, all honest:
    1. Doc present? A missing ARCHITECTURE.md is the primary "stale" case.
    2. mtime freshness — any source file newer than the doc (FreshnessReport).
    3. Commit drift — the doc's stored git_commit vs the current HEAD.
    """
    from rich.table import Table

    from patchi.core.brain.docs_generator import _check_docs_freshness

    docs_dir = root / "docs"
    doc_path = docs_dir / "ARCHITECTURE.md"
    meta_path = docs_dir / ".patchi-meta.json"

    rows: list[tuple[str, str, str]] = []

    if not doc_path.exists():
        rows.append(("doc", "MISSING", "No docs/ARCHITECTURE.md — run `p docs` to generate"))
    else:
        rows.append(("doc", "OK", str(doc_path)))

    report = _check_docs_freshness(docs_dir, root)
    if doc_path.exists():
        if report.fresh:
            rows.append(("freshness", "OK", "No source file is newer than the doc"))
        else:
            n = len(report.stale_files)
            sample = ", ".join(report.stale_files[:3])
            rows.append(
                (
                    "freshness",
                    "STALE",
                    f"{n} source file(s) newer than doc: {sample}{'…' if n > 3 else ''}",
                )
            )

    # Commit drift.
    current_commit = None
    try:
        import subprocess

        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            current_commit = result.stdout.strip()
    except Exception:
        pass

    meta: dict = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as e:
            _log.debug("metadata unreadable: %s", e)
            rows.append(("metadata", "ERROR", f".patchi-meta.json unreadable: {e}"))

    stored_commit = meta.get("git_commit")
    if stored_commit and current_commit:
        if stored_commit == current_commit:
            rows.append(("commit", "OK", current_commit[:12]))
        else:
            rows.append(
                (
                    "commit",
                    "DRIFT",
                    f"doc generated at {stored_commit[:12]}, HEAD is {current_commit[:12]}",
                )
            )
    elif current_commit:
        rows.append(("commit", "UNKNOWN", "No metadata — run `p docs` to write .patchi-meta.json"))

    table = Table(title="Docs freshness check", show_header=True, header_style="bold")
    table.add_column("Signal")
    table.add_column("State")
    table.add_column("Detail", max_width=70)
    ok = True
    for signal, state, detail in rows:
        style = "green" if state == "OK" else ("red" if state in {"MISSING", "STALE", "DRIFT", "ERROR"} else "yellow")
        if state != "OK":
            ok = False
        table.add_row(signal, f"[{style}]{state}[/{style}]", detail)
    console.print(table)

    if meta:
        console.print(
            f"[dim]generated_at={meta.get('generated_at', '?')}"
            f" patchi={meta.get('patchi_version', '?')}"
            f" source_files={meta.get('source_file_count', '?')}[/dim]"
        )

    if ok:
        console.print("[green]Docs are up to date.[/green]")
    else:
        console.print("[yellow]Docs need attention — run `p docs --regen` to refresh.[/yellow]")
