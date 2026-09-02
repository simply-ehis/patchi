"""
Import graph — directed graph of file import relationships.

Builds a directed graph where edges mean "A imports B".
Uses FileInfo.imports (already parsed by scanner) — no re-parsing.

Used for:
- Dead file detection (files with no incoming edges from app code)
- Circular dependency detection
- Blast radius calculation (how many files break if X changes)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import FileInfo


# ── Known source file extensions (for cross-language resolution) ────────

KNOWN_EXTENSIONS = frozenset(
    {
        ".py",
        ".pyw",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".mts",
        ".rs",
        ".go",
        ".java",
        ".c",
        ".h",
        ".cpp",
        ".cxx",
        ".cc",
        ".hpp",
        ".swift",
        ".rb",
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".kt",
        ".scala",
        ".cs",
        ".dart",
        ".svelte",
        # Config / data languages (parsed by scanner but not TREE_SITTER_LANGS)
        ".html",
        ".htm",
        ".jinja",
        ".jinja2",
        ".j2",
        ".css",
        ".scss",
        ".sass",
        ".sh",
        ".bash",
        ".zsh",
        ".json",
        ".jsonc",
        ".yml",
        ".yaml",
        ".sql",
        # Extensionless filename-based languages (Dockerfile, Makefile, etc.)
    }
)

# ── Data types ─────────────────────────────────────────────────────────────────


@dataclass
class CircularDep:
    """A detected circular import cycle."""

    cycle: list[str]  # ordered list of files in the cycle

    @property
    def short_label(self) -> str:
        return " → ".join(self.cycle)


class ImportGraph:
    """
    Directed graph of import relationships.

    edges[A] = {B, C}  means A imports B and C
    reverse[B] = {A}   means A imports B (who imports B)
    """

    def __init__(self) -> None:
        self.nodes: set[str] = set()
        self.edges: dict[str, set[str]] = defaultdict(set)
        self.reverse: dict[str, set[str]] = defaultdict(set)

    def add_edge(self, importer: str, imported: str) -> None:
        """Record that `importer` imports `imported`."""
        self.nodes.add(importer)
        self.nodes.add(imported)
        self.edges[importer].add(imported)
        self.reverse[imported].add(importer)

    def to_dict(self) -> dict:
        return {
            "nodes": sorted(self.nodes),
            "edges": {k: sorted(v) for k, v in self.edges.items()},
        }

    def get_file_context(self, file_path: str) -> dict:
        """Return import context for a file: what it imports, what imports it."""
        return {
            "file": file_path,
            "imports": sorted(self.edges.get(file_path, set())),
            "imported_by": sorted(self.reverse.get(file_path, set())),
        }

    def get_transitive_dependents(self, file_path: str) -> set[str]:
        """All files that directly or indirectly depend on the given file."""
        visited: set[str] = set()
        queue = list(self.reverse.get(file_path, set()))
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            queue.extend(self.reverse.get(current, set()) - visited)
        return visited

    def format_fix_context(self, file_path: str, max_imports: int = 15) -> str:
        """Human-readable context block for AI fix agents."""
        ctx = self.get_file_context(file_path)
        lines: list[str] = []
        if ctx["imports"]:
            truncated = ctx["imports"][:max_imports]
            lines.append(f"  Imports ({len(ctx['imports'])}): " + ", ".join(truncated))
            if len(ctx["imports"]) > max_imports:
                lines.append(f"    ... and {len(ctx['imports']) - max_imports} more")
        if ctx["imported_by"]:
            truncated = ctx["imported_by"][:max_imports]
            lines.append(f"  Imported by ({len(ctx['imported_by'])}): " + ", ".join(truncated))
            if len(ctx["imported_by"]) > max_imports:
                lines.append(f"    ... and {len(ctx['imported_by']) - max_imports} more")
        if not ctx["imports"] and not ctx["imported_by"]:
            lines.append("  (no import relationships found)")
        return "\n".join(lines)

    def to_dot(self, max_nodes: int = 200) -> str:
        """DOT/Graphviz export for visualization (§1.3.3)."""
        lines = ["digraph G {", "  rankdir=LR;", '  node [shape=box, style=rounded];']
        nodes = sorted(self.nodes)[:max_nodes]
        node_set = set(nodes)
        for n in nodes:
            safe = n.replace('"', '\\"')
            lines.append(f'  "{safe}";')
        for src in nodes:
            for tgt in sorted(self.edges.get(src, [])):
                if tgt in node_set:
                    lines.append(f'  "{src.replace(chr(34), chr(92)+chr(34))}" -> "{tgt.replace(chr(34), chr(92)+chr(34))}";')
        lines.append("}")
        return "\n".join(lines)


# ── Builder ────────────────────────────────────────────────────────────────────


def build_graph(files: list[FileInfo], root: Path) -> ImportGraph:
    """
    Build an import graph from a list of FileInfo objects.

    Reads imports from FileInfo.imports (already parsed by scanner).
    Only resolves imports to local project files; external packages are ignored.
    """
    graph = ImportGraph()

    # Register every scanned file as a node
    local_files: set[str] = set()
    for fi in files:
        graph.nodes.add(fi.path)
        local_files.add(fi.path)

    # Resolve each file's imports to local files
    for fi in files:
        for imp in fi.imports:
            resolved = _resolve_to_local(imp.source, fi.path, local_files)
            if resolved and resolved != fi.path:
                graph.add_edge(fi.path, resolved)

    return graph


def build_import_graph(root: Path) -> ImportGraph:
    """Build an import graph by scanning root directly (no FileInfo list)."""
    from .scanner import FileScanner

    scanner = FileScanner(root)
    files = scanner.scan()
    return build_graph(files, root)


# Alias used by some older callers
build_graph_from_root = build_import_graph


# ── Cross-language import resolution ──────────────────────────────────────────


def _resolve_to_local(
    imp: str,
    from_file: str,
    local_files: set[str],
) -> str | None:
    """
    Try to resolve an import string to a local project file path.

    Handles multiple import conventions across languages:
      - Relative paths (.utils, ../helper, ./foo)
      - Path-style imports (fmt, myproject/pkg/util)
      - Dotted module names (os.path, java.util.List)
      - Rust :: separators (std::collections::HashMap, crate::mod::fn)
      - Simple filenames (stdio.h, myheader.h, json)
    """
    imp = imp.strip("\"'<>")
    if not imp:
        return None

    source_dir = Path(from_file).parent

    # Strategy 1: Relative path starting with . or /
    if imp.startswith(".") or imp.startswith("/"):
        return _resolve_relative(imp, source_dir, local_files)

    # Strategy 2: Path-style import (contains /)
    if "/" in imp:
        return _resolve_path(imp, source_dir, local_files)

    # Strategy 3: Rust :: separator
    if "::" in imp:
        path_style = imp.replace("::", "/")
        candidate = _resolve_path(path_style, source_dir, local_files)
        if candidate:
            return candidate
        for prefix in ("crate/", "self/", "super/"):
            if path_style.startswith(prefix):
                sub = path_style[len(prefix) :]
                r = _resolve_path(sub, source_dir, local_files)
                if r:
                    return r
        return None

    # Strategy 4: Dotted module (Python, Java)
    if "." in imp:
        return _resolve_dotted(imp, source_dir, local_files)

    # Strategy 5: Bare name — try as file, then as dir/name
    result = _try_extensions(imp, local_files)
    if result:
        return result
    candidate = (source_dir / imp).as_posix()
    return _try_extensions(candidate, local_files)


def _resolve_relative(imp: str, source_dir: Path, local_files: set[str]) -> str | None:
    """Resolve a relative import like .utils, ../helper, /src/foo."""
    if imp.startswith("."):
        level = 0
        while level < len(imp) and imp[level] == ".":
            level += 1
        remainder = imp[level:]
        target_dir = source_dir
        for _ in range(level - 1):
            target_dir = target_dir.parent
        if remainder:
            candidate = (target_dir / remainder).as_posix()
        else:
            candidate = (target_dir / "__init__").as_posix()
        return _try_extensions(candidate, local_files)

    if imp.startswith("/"):
        candidate = imp.lstrip("/")
        return _try_extensions(candidate, local_files) if candidate else None

    return None


def _resolve_path(imp: str, source_dir: Path, local_files: set[str]) -> str | None:
    """Resolve a path-style import relative to source file's directory."""
    # Try direct resolution relative to source directory
    candidate = (source_dir / imp).as_posix()
    result = _try_extensions(candidate, local_files)
    if result:
        return result
    # For module-prefixed paths (Go, etc.), strip leading components
    # e.g. "example.com/app/src/greeter" → strip "example.com" → strip "app" → "src/greeter"
    parts = imp.split("/")
    for start in range(1, len(parts)):
        sub = "/".join(parts[start:])
        # Try relative to source directory
        candidate = (source_dir / sub).as_posix()
        result = _try_extensions(candidate, local_files)
        if result:
            return result
        # Try as absolute from project root
        result = _try_extensions(sub, local_files)
        if result:
            return result
    return None


def _resolve_dotted(imp: str, source_dir: Path, local_files: set[str]) -> str | None:
    """Resolve a dotted module import (Python, Java)."""
    # Try the original string as a path first (handles "util.h", "theme.css", "db.php")
    result = _resolve_path(imp, source_dir, local_files)
    if result:
        return result
    parts = imp.split(".")
    for length in range(len(parts), 0, -1):
        candidate = "/".join(parts[:length])
        result = _try_extensions(candidate, local_files)
        if result:
            return result
    return None


_JAVA_SRC_PREFIXES = ("src/main/java/", "src/test/java/", "src/main/kotlin/", "src/")

def _try_extensions(base_path: str, local_files: set[str]) -> str | None:
    """Try appending each known extension and check if the file exists in local_files."""
    base = base_path.lstrip("/")

    # Try the path itself (handles extensionless files like Makefile, Dockerfile)
    if base in local_files:
        return base

    # If the path already has a known extension, try it directly first
    if any(base.endswith(ext) for ext in KNOWN_EXTENSIONS):
        if base in local_files:
            return base
        # Also try under Java/Kotlin src prefixes for dotted com.example.Foo
        for pref in _JAVA_SRC_PREFIXES:
            if (pref + base) in local_files:
                return pref + base

    for ext in KNOWN_EXTENSIONS:
        candidate = base + ext
        if candidate in local_files:
            return candidate
        for pref in _JAVA_SRC_PREFIXES:
            if (pref + candidate) in local_files:
                return pref + candidate
        init_candidate = base + "/__init__" + ext
        if init_candidate in local_files:
            return init_candidate
        # Go/Rust directory convention: "pkg" → "pkg/pkg.go" or "pkg/mod.rs"
        last = base.rsplit("/", 1)[-1]
        dir_candidate = base + "/" + last + ext
        if dir_candidate in local_files:
            return dir_candidate
        if ext == ".rs":
            mod_candidate = base + "/mod.rs"
            if mod_candidate in local_files:
                return mod_candidate
    return None


# ── Circular dependency detection ──────────────────────────────────────────────


def find_circular_dependencies(graph: ImportGraph) -> list[CircularDep]:
    """
    Detect circular import chains via DFS.
    Returns deduplicated CircularDep objects.
    """
    visited: set[str] = set()
    rec_stack: set[str] = set()
    raw_cycles: list[tuple[str, ...]] = []

    def dfs(node: str, path: list[str]) -> None:
        visited.add(node)
        rec_stack.add(node)
        path.append(node)
        for neighbour in sorted(graph.edges.get(node, set())):
            if neighbour not in visited:
                dfs(neighbour, path)
            elif neighbour in rec_stack:
                idx = path.index(neighbour)
                cycle = tuple(path[idx:])
                min_i = cycle.index(min(cycle))
                canonical = cycle[min_i:] + cycle[:min_i]
                raw_cycles.append(canonical)
        path.pop()
        rec_stack.discard(node)

    for node in sorted(graph.nodes):
        if node not in visited:
            dfs(node, [])

    seen: set[tuple[str, ...]] = set()
    result: list[CircularDep] = []
    for c in raw_cycles:
        if c not in seen:
            seen.add(c)
            result.append(CircularDep(cycle=list(c) + [c[0]]))
    return result


# ── Dead file detection ────────────────────────────────────────────────────────

_INTERNAL_SEGMENTS = frozenset(
    {
        "cli",
        "core",
        "web",
        "tests",
        "test",
        "commands",
        "notifications",
        "hosted",
        "docs",
        "scripts",
        "benchmark",
        "examples",
        "example",
        "demo",
    }
)

_ENTRY_POINT_STEMS = frozenset(
    {
        "main",
        "app",
        "index",
        "__init__",
        "setup",
        "cli",
        "server",
        "api",
        "manage",
        "wsgi",
        "asgi",
        "run",
        "start",
    }
)


def find_dead_files(
    files: list[FileInfo],
    graph: ImportGraph,
) -> list[str]:
    """
    Return paths of files that nothing in the project imports.

    Excludes:
    - Files in internal package folders (cli/, core/, web/, tests/, ...)
    - Entry-point files (main.py, app.py, index.py, ...)
    - Test files (test_*.py, *_test.py)
    """
    dead: list[str] = []
    for fi in files:
        path = fi.path
        parts = path.lower().split("/")

        if any(seg in _INTERNAL_SEGMENTS for seg in parts):
            continue

        stem = Path(path).stem
        if stem.startswith("test_") or stem.endswith("_test"):
            continue

        if stem in _ENTRY_POINT_STEMS:
            continue

        if not graph.reverse.get(path):
            dead.append(path)

    return dead
