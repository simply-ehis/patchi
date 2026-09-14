"""
Plugin management commands for Patchi.

Usage:
    p plugins list              List all registered plugins
    p plugins run <name>        Run a specific plugin
    p plugins run-all           Run all plugins
    p plugins info <name>       Show plugin details
"""

from __future__ import annotations

import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from patchi.core.plugins.analyzer import AnalyzerContext
from patchi.core.plugins.registry import get_registry

console = Console()


def cmd_plugins(args: list[str]) -> None:
    """Handle plugin commands."""
    if not args:
        _show_help()
        return

    cmd = args[0]

    if cmd == "list":
        _list_plugins()
    elif cmd == "run" and len(args) > 1:
        _run_plugin(args[1])
    elif cmd == "run-all":
        _run_all_plugins()
    elif cmd == "info" and len(args) > 1:
        _show_plugin_info(args[1])
    else:
        _show_help()


def _show_help() -> None:
    """Show help message."""
    console.print(
        Panel.fit(
            "[bold]Patchi Plugin System[/bold]\n\n"
            "Commands:\n"
            "  p plugins list              List all registered plugins\n"
            "  p plugins run <name>        Run a specific plugin\n"
            "  p plugins run-all           Run all plugins\n"
            "  p plugins info <name>       Show plugin details\n\n"
            "Plugin directories:\n"
            "  Built-in: patchi/core/plugins/analyzers/\n"
            "  User:     ~/.patchi/plugins/\n"
            "  Project:  .patchi/plugins/",
            title="Plugin Help",
        )
    )


def _list_plugins() -> None:
    """List all registered plugins."""
    registry = get_registry()
    analyzers = registry.list_analyzers(enabled_only=False)

    if not analyzers:
        console.print("[yellow]No plugins found. Discovering...[/yellow]")
        registry.discover()
        analyzers = registry.list_analyzers(enabled_only=False)

    table = Table(title="Registered Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Priority", justify="right")
    table.add_column("Enabled", justify="center")
    table.add_column("Description")

    for analyzer in analyzers:
        enabled = "✓" if analyzer.enabled else "✗"
        style = "green" if analyzer.enabled else "dim"
        table.add_row(
            analyzer.name,
            analyzer.version,
            str(analyzer.priority),
            f"[{style}]{enabled}[/{style}]",
            analyzer.description[:50] + "..." if len(analyzer.description) > 50 else analyzer.description,
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(analyzers)} plugins[/dim]")


def _run_plugin(name: str) -> None:
    """Run a specific plugin."""
    registry = get_registry()
    analyzer = registry.get(name)

    if not analyzer:
        console.print(f"[red]Plugin '{name}' not found[/red]")
        console.print("[dim]Run 'p plugins list' to see available plugins[/dim]")
        return

    console.print(f"[bold]Running plugin: {analyzer.name} v{analyzer.version}[/bold]")

    # Build context from current project
    root = Path.cwd()
    context = AnalyzerContext(
        root=root,
        config=_load_config(root),
    )

    # Load files
    console.print("[dim]Loading project files...[/dim]")
    context.files = _load_files(root)

    # Run the analyzer
    console.print(f"[dim]Analyzing {len(context.files)} files...[/dim]")
    t0 = time.time()
    result = registry.run(name, context)
    duration = time.time() - t0

    # Display results
    _display_result(analyzer.name, result, duration)


def _run_all_plugins() -> None:
    """Run all plugins."""
    registry = get_registry()
    analyzers = registry.list_analyzers(enabled_only=True)

    if not analyzers:
        console.print("[yellow]No plugins found[/yellow]")
        return

    console.print(f"[bold]Running {len(analyzers)} plugins...[/bold]")

    # Build context
    root = Path.cwd()
    context = AnalyzerContext(
        root=root,
        config=_load_config(root),
    )

    # Load files
    console.print("[dim]Loading project files...[/dim]")
    context.files = _load_files(root)

    # Run all analyzers
    t0 = time.time()
    results = registry.run_all(context)
    duration = time.time() - t0

    # Display results
    total_findings = sum(len(r.findings) for r in results.values())
    console.print(f"\n[bold green]✓ Completed {len(results)} plugins in {duration:.1f}s[/bold green]")
    console.print(f"[dim]Total findings: {total_findings}[/dim]")

    for name, result in results.items():
        if result.findings:
            console.print(f"\n[bold]{name}:[/bold] {len(result.findings)} findings")
            for finding in result.findings[:5]:  # Show first 5
                severity_color = {
                    "critical": "red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "dim",
                }.get(finding.severity.value, "white")
                console.print(
                    f"  [{severity_color}]●[/{severity_color}] {finding.file}:{finding.line} - {finding.message}"
                )


def _show_plugin_info(name: str) -> None:
    """Show detailed info about a plugin."""
    registry = get_registry()
    analyzer = registry.get(name)

    if not analyzer:
        console.print(f"[red]Plugin '{name}' not found[/red]")
        return

    info = analyzer.describe()

    console.print(
        Panel.fit(
            f"[bold]Name:[/bold] {info['name']}\n"
            f"[bold]Version:[/bold] {info['version']}\n"
            f"[bold]Description:[/bold] {info['description']}\n"
            f"[bold]Priority:[/bold] {info['priority']}\n"
            f"[bold]Timeout:[/bold] {info['timeout']}s\n"
            f"[bold]Enabled:[/bold] {info['enabled']}\n"
            f"[bold]Languages:[/bold] {', '.join(info['supported_languages']) or 'all'}\n"
            f"[bold]File Patterns:[/bold] {', '.join(info['supported_file_patterns']) or 'all'}",
            title=f"Plugin: {name}",
        )
    )


def _load_config(root: Path) -> dict:
    """Load project config."""
    try:
        from patchi.core import config as cfg

        return cfg.load(root)
    except Exception:
        return {}


def _load_files(root: Path) -> list:
    """Load project files for analysis."""
    from patchi.core.plugins.analyzer import FileNode

    files = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".patchi", "venv", ".venv"}
    skip_extensions = {".pyc", ".pyo", ".so", ".dll", ".exe", ".bin"}

    for path in root.rglob("*"):
        if path.is_file():
            # Skip directories
            if any(skip in path.parts for skip in skip_dirs):
                continue
            if path.suffix in skip_extensions:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(path.relative_to(root))

                # Detect language
                language = _detect_language(path)

                files.append(
                    FileNode(
                        path=rel_path,
                        content=content,
                        language=language,
                        size=path.stat().st_size,
                    )
                )
            except Exception:
                continue

    return files


def _detect_language(path: Path) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "javascript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".rb": "ruby",
        ".php": "php",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".html": "html",
        ".css": "css",
        ".scss": "scss",
        ".less": "less",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".xml": "xml",
        ".sql": "sql",
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        ".md": "markdown",
        ".txt": "text",
    }
    return ext_map.get(path.suffix.lower(), "unknown")


def _display_result(name: str, result, duration: float) -> None:
    """Display analysis results."""
    if result.errors:
        console.print("[red]Errors:[/red]")
        for error in result.errors:
            console.print(f"  ✗ {error}")
        return

    console.print(f"\n[bold green]✓ {name} completed in {duration:.1f}s[/bold green]")
    console.print(f"[dim]Files analyzed: {result.files_analyzed}[/dim]")
    console.print(f"[dim]Findings: {len(result.findings)}[/dim]")

    if result.findings:
        console.print("\n[bold]Findings:[/bold]")
        for finding in result.findings[:10]:  # Show first 10
            severity_color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }.get(finding.severity.value, "white")
            console.print(f"  [{severity_color}]●[/{severity_color}] {finding.file}:{finding.line} - {finding.message}")

        if len(result.findings) > 10:
            console.print(f"  [dim]... and {len(result.findings) - 10} more[/dim]")
