"""
Symbol Graph — function/class/route-level dependency graph.

Parallel to ImportGraph (file-level). Uses tree-sitter for accurate
AST-based symbol extraction. Backed by SQLite for incremental updates.

SymbolNode types:
  - function, async_function, method, async_method
  - class
  - route (web route handler)
  - variable (module-level exported)
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from patchi.core.brain.languages import Lang, detect_language, get_parser
from patchi.core.brain.scanner import FileInfo

# ── Constants ───────────────────────────────────────────────────────────────────

SYMBOL_GRAPH_DB = "symbol_graph.db"

# Serializes ensure_built()'s check-then-build so concurrent callers cannot
# race full rebuilds (DELETE + INSERT) on the same SQLite file.
_BUILD_LOCK = threading.Lock()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS symbols (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    parent_id INTEGER,
    docstring TEXT,
    language TEXT NOT NULL,
    hash TEXT NOT NULL,
    decorators TEXT DEFAULT '',
    params TEXT DEFAULT '',
    is_exported INTEGER DEFAULT 0,
    UNIQUE(name, file, line)
);

CREATE TABLE IF NOT EXISTS edges (
    source_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'calls',
    PRIMARY KEY (source_id, target_id, kind),
    FOREIGN KEY (source_id) REFERENCES symbols(id),
    FOREIGN KEY (target_id) REFERENCES symbols(id)
);

CREATE INDEX IF NOT EXISTS idx_symbols_file ON symbols(file);
CREATE INDEX IF NOT EXISTS idx_symbols_kind ON symbols(kind);
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
"""

_RUST_ROUTE_ATTR_RE = re.compile(
    r"#\[\s*(get|post|put|delete|patch|head|options|connect|trace)\s*\(\s*\"([^\"]+)\"\s*\)",
    re.IGNORECASE,
)
_SVELTE_SCRIPT_RE = re.compile(r"<script[^>]*>", re.IGNORECASE)


# ── Symbol kind enum ────────────────────────────────────────────────────────────


import logging
_log = logging.getLogger("patchi.brain.symbol_graph")

class SymbolKind(str, Enum):
    FUNCTION = "function"
    ASYNC_FUNCTION = "async_function"
    METHOD = "method"
    ASYNC_METHOD = "async_method"
    CLASS = "class"
    ROUTE = "route"
    VARIABLE = "variable"


# ── Data types ──────────────────────────────────────────────────────────────────


@dataclass
class SymbolNode:
    id: int = 0
    name: str = ""
    kind: str = ""
    file: str = ""
    line: int = 0
    end_line: int = 0
    parent_id: int | None = None
    docstring: str = ""
    language: str = ""
    hash: str = ""
    decorators: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    is_exported: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "parent_id": self.parent_id,
            "language": self.language,
            "decorators": self.decorators,
            "params": self.params,
            "is_exported": self.is_exported,
        }

    @property
    def qualified_name(self) -> str:
        """Dotted module path + symbol name, e.g. 'src.main.handler'."""
        if self.file and self.file != ".":
            mod = self.file[:-3] if self.file.endswith(".py") else self.file
            mod = mod.replace("/", ".").replace("\\", ".")
            return f"{mod}.{self.name}"
        return self.name


@dataclass
class GraphDiff:
    added: list[SymbolNode] = field(default_factory=list)
    removed: list[SymbolNode] = field(default_factory=list)
    modified: list[SymbolNode] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def summary(self) -> str:
        parts = []
        if self.added:
            parts.append(f"+{len(self.added)} added")
        if self.removed:
            parts.append(f"-{len(self.removed)} removed")
        if self.modified:
            parts.append(f"~{len(self.modified)} modified")
        return ", ".join(parts) if parts else "no changes"


# ── SymbolGraph ─────────────────────────────────────────────────────────────────


class SymbolGraph:
    """Symbol-level dependency graph backed by SQLite."""

    def __init__(self, root: Path):
        self.root = root
        self.db_path = root / ".patchi" / SYMBOL_GRAPH_DB
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._get_conn()
        conn.executescript(SCHEMA_SQL)

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── Public API ──────────────────────────────────────────────────────────

    def build_from_files(self, files: list[FileInfo]) -> int:
        """Full rebuild from a list of FileInfo objects. Returns symbol count."""
        conn = self._get_conn()
        conn.execute("DELETE FROM edges")
        conn.execute("DELETE FROM symbols")
        conn.execute("DELETE FROM meta")

        count = 0
        for fi in files:
            symbols = self._extract_symbols(fi)
            for sym in symbols:
                self._insert_symbol(conn, sym, fi.path)
                count += 1

        self._build_edges(conn, files)
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            ("last_build", str(time.time())),
        )
        conn.commit()
        return count

    def build_from_root(self) -> int:
        """Build by scanning root directory directly."""
        from patchi.core.brain.scanner import FileScanner

        scanner = FileScanner(self.root)
        files = scanner.scan()
        return self.build_from_files(files)

    def patch(self, changed_files: list[Path]) -> GraphDiff:
        """Incremental update: re-parse only changed files. Returns diff."""
        diff = GraphDiff()
        conn = self._get_conn()

        for file_path in changed_files:
            try:
                rel = file_path.relative_to(self.root).as_posix()
            except ValueError:
                continue

            lang = detect_language(file_path)
            if lang == Lang.UNKNOWN:
                continue

            old_symbols = self._get_symbols_in_file(conn, rel)
            for sym in old_symbols:
                diff.removed.append(sym)
            conn.execute("DELETE FROM symbols WHERE file = ?", (rel,))

            content = file_path.read_text(encoding="utf-8", errors="ignore")
            fi = FileInfo(
                path=rel,
                language=lang,
                size_bytes=len(content.encode("utf-8")),
                lines=content.count("\n") + 1,
            )

            new_symbols = self._extract_symbols(fi)
            for sym in new_symbols:
                self._insert_symbol(conn, sym, rel)
                old = next((s for s in old_symbols if s.name == sym.name and s.line == sym.line), None)
                if old and old.hash != sym.hash:
                    diff.modified.append(sym)
                elif not old:
                    diff.added.append(sym)

            for sym in list(diff.removed):
                still_exists = any(
                    s.name == sym.name and s.line == sym.line for s in new_symbols
                )
                if still_exists:
                    diff.removed.remove(sym)

        conn.commit()
        return diff

    def get_symbol(
        self, name: str, file: str | None = None, line: int | None = None
    ) -> SymbolNode | None:
        """Look up a symbol by name (and optionally file+line)."""
        conn = self._get_conn()
        if file and line:
            cur = conn.execute(
                "SELECT * FROM symbols WHERE name = ? AND file = ? AND line = ?",
                (name, file, line),
            )
        elif file:
            cur = conn.execute(
                "SELECT * FROM symbols WHERE name = ? AND file = ?", (name, file)
            )
        else:
            cur = conn.execute(
                "SELECT * FROM symbols WHERE name = ? LIMIT 1", (name,)
            )
        row = cur.fetchone()
        return self._row_to_symbol(row) if row else None

    def get_symbols_in_file(self, file: str) -> list[SymbolNode]:
        """All symbols defined in a file."""
        return self._get_symbols_in_file(self._get_conn(), file)

    def get_symbols_by_kind(self, kind: SymbolKind | str) -> list[SymbolNode]:
        """All symbols of a given kind."""
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT * FROM symbols WHERE kind = ? ORDER BY file, line", (kind.value if isinstance(kind, SymbolKind) else kind,)
        )
        return [self._row_to_symbol(r) for r in cur.fetchall()]

    def get_all_symbols(self) -> list[SymbolNode]:
        """Every symbol in the graph, ordered by file and line."""
        conn = self._get_conn()
        cur = conn.execute("SELECT * FROM symbols ORDER BY file, line")
        return [self._row_to_symbol(r) for r in cur.fetchall()]

    def ensure_built(self) -> int:
        """Build the graph from root if it is empty. Returns symbol count.

        Idempotent — a populated DB is left untouched, so this is safe to call
        before every query site (e.g. governor neighborhood builders) without
        re-scanning the whole project on each invocation.

        Thread-safe: a module-level lock serializes the check-then-build, so
        two concurrent governor paths can never both see count()==0 and race
        DELETE/INSERT on the same SQLite file.
        """
        count = self.count()
        if count > 0:
            return count
        with _BUILD_LOCK:
            # Re-check inside the lock — another caller may have built it.
            count = self.count()
            if count > 0:
                return count
            return self.build_from_root()

    def get_dependents(self, symbol_name: str, file: str | None = None) -> list[SymbolNode]:
        """Symbols that reference (depend on) the given symbol."""
        conn = self._get_conn()
        if file:
            cur = conn.execute(
                """SELECT s.* FROM symbols s
                   JOIN edges e ON s.id = e.source_id
                   JOIN symbols t ON t.id = e.target_id
                   WHERE t.name = ? AND t.file = ?""",
                (symbol_name, file),
            )
        else:
            cur = conn.execute(
                """SELECT s.* FROM symbols s
                   JOIN edges e ON s.id = e.source_id
                   JOIN symbols t ON t.id = e.target_id
                   WHERE t.name = ?""",
                (symbol_name,),
            )
        return [self._row_to_symbol(r) for r in cur.fetchall()]

    def get_dependencies(self, symbol_id: int) -> list[SymbolNode]:
        """Symbols that the given symbol references."""
        conn = self._get_conn()
        cur = conn.execute(
            """SELECT s.* FROM symbols s
               JOIN edges e ON s.id = e.target_id
               WHERE e.source_id = ?""",
            (symbol_id,),
        )
        return [self._row_to_symbol(r) for r in cur.fetchall()]

    def get_transitive_dependents(
        self, symbol_name: str, file: str, max_depth: int = 5
    ) -> list[SymbolNode]:
        """All symbols that transitively depend on the given symbol."""
        visited: set[int] = set()
        result: list[SymbolNode] = []
        queue: list[tuple[int, int]] = []
        symbol = self.get_symbol(symbol_name, file)
        if not symbol:
            return []
        queue.extend((d.id, 1) for d in self.get_dependents(symbol_name, file))

        while queue:
            sid, depth = queue.pop(0)
            if sid in visited or depth > max_depth:
                continue
            visited.add(sid)
            s = self._get_symbol_by_id(sid)
            if s:
                result.append(s)
                queue.extend((d.id, depth + 1) for d in self.get_dependents(s.name, s.file))

        return result

    def get_route_endpoints(self) -> list[SymbolNode]:
        """All route handler symbols."""
        return self.get_symbols_by_kind(SymbolKind.ROUTE)

    def count(self) -> int:
        conn = self._get_conn()
        cur = conn.execute("SELECT COUNT(*) FROM symbols")
        return cur.fetchone()[0]

    def export_json(self) -> dict:
        """Export entire graph as JSON (for web UI / CLI display)."""
        conn = self._get_conn()
        symbols = [
            self._row_to_symbol(r).to_dict()
            for r in conn.execute("SELECT * FROM symbols ORDER BY file, line").fetchall()
        ]
        edges = [
            {"source": r[0], "target": r[1], "kind": r[2]}
            for r in conn.execute("SELECT * FROM edges").fetchall()
        ]
        meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
        return {"symbols": symbols, "edges": edges, "meta": meta, "count": len(symbols)}

    # ── Internal: Extraction ───────────────────────────────────────────────

    def _extract_symbols(self, fi: FileInfo) -> list[SymbolNode]:
        """Extract SymbolNodes from a single file using tree-sitter or regex."""
        lang = fi.language
        abs_path = self.root / fi.path
        if not abs_path.exists():
            return []

        # Read as bytes for tree-sitter (byte offsets), decode to str for ast fallback
        raw_bytes = abs_path.read_bytes()
        content_str = raw_bytes.decode("utf-8", errors="replace")

        if lang == Lang.PYTHON:
            return self._extract_python(raw_bytes, content_str, fi.path)
        elif lang in (Lang.JAVASCRIPT, Lang.TYPESCRIPT):
            return self._extract_js_ts(raw_bytes, content_str, fi.path, lang)
        elif lang == Lang.RUST:
            return self._extract_rust(raw_bytes, content_str, fi.path)
        elif lang == Lang.SVELTE:
            return self._extract_svelte(raw_bytes, content_str, fi.path)
        elif lang == Lang.JAVA:
            return self._extract_java(raw_bytes, content_str, fi.path)
        elif lang == Lang.GO:
            return self._extract_go(raw_bytes, content_str, fi.path)
        elif lang in (Lang.C, Lang.CPP):
            return self._extract_c_cpp(raw_bytes, content_str, fi.path, lang)
        elif lang == Lang.SWIFT:
            return self._extract_swift(raw_bytes, content_str, fi.path)
        elif lang == Lang.RUBY:
            return self._extract_ruby(raw_bytes, content_str, fi.path)
        elif lang == Lang.PHP:
            return self._extract_generic_ts(raw_bytes, content_str, fi.path, lang,
                function_types={"function_definition"},
                method_types={"method_declaration"},
                class_types={"class_declaration"},
            )
        elif lang == Lang.C_SHARP:
            return self._extract_generic_ts(raw_bytes, content_str, fi.path, lang,
                method_types={"method_declaration"},
                class_types={"class_declaration"},
            )
        elif lang == Lang.KOTLIN:
            return self._extract_generic_ts(raw_bytes, content_str, fi.path, lang,
                function_types={"function_declaration"},
                method_types={"function_declaration"},
                class_types={"class_declaration"},
            )
        elif lang == Lang.DART:
            return self._extract_generic_ts(raw_bytes, content_str, fi.path, lang,
                function_types={"function_declaration"},
                method_types={"method_declaration"},
                class_types={"class_definition"},
            )
        elif lang == Lang.BASH:
            return self._extract_generic_ts(raw_bytes, content_str, fi.path, lang,
                function_types={"function_definition"},
            )
        elif lang in (Lang.CSS, Lang.SQL):
            return []
        else:
            return []

    def _extract_python(
        self, raw_bytes: bytes, content_str: str, file: str
    ) -> list[SymbolNode]:
        """Python symbols via tree-sitter or ast."""
        symbols: list[SymbolNode] = []

        parser = get_parser(Lang.PYTHON)
        if parser:
            try:
                tree = parser.parse(raw_bytes)
                self._walk_python(tree.root_node, raw_bytes, content_str, file, symbols, None)
                if symbols:
                    return symbols
            except Exception as e:
                _log.warning("SymbolGraph._extract_python failed: %s", e)

        return self._extract_python_ast(content_str, file)

    def _extract_python_ast(self, content: str, file: str) -> list[SymbolNode]:
        """Fallback Python symbol extraction using stdlib ast."""
        import ast

        symbols: list[SymbolNode] = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return symbols

        lines = content.split("\n")

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                end = getattr(node, "end_lineno", node.lineno) or node.lineno
                sym = SymbolNode(
                    name=node.name,
                    kind=SymbolKind.ASYNC_FUNCTION if isinstance(node, ast.AsyncFunctionDef) else SymbolKind.FUNCTION,
                    file=file,
                    line=node.lineno,
                    end_line=end,
                    docstring=ast.get_docstring(node) or "",
                    language="python",
                    decorators=[d.id if isinstance(d, ast.Name) else "" for d in node.decorator_list if isinstance(d, ast.Name)],
                    params=[a.arg for a in node.args.args] if hasattr(node.args, "args") else [],
                    is_exported=not node.name.startswith("_") or file == "__init__.py",
                    hash=_content_hash(lines[node.lineno - 1] if node.lineno <= len(lines) else ""),
                )
                symbols.append(sym)

            elif isinstance(node, ast.ClassDef):
                end = getattr(node, "end_lineno", node.lineno) or node.lineno
                sym = SymbolNode(
                    name=node.name,
                    kind=SymbolKind.CLASS,
                    file=file,
                    line=node.lineno,
                    end_line=end,
                    docstring=ast.get_docstring(node) or "",
                    language="python",
                    is_exported=True,
                    hash=_content_hash(lines[node.lineno - 1] if node.lineno <= len(lines) else ""),
                )
                symbols.append(sym)

        return symbols

    def _walk_python(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        """Walk Python tree-sitter CST for function/class/route symbols."""
        buf = raw_bytes  # byte buffer for tree-sitter byte-offset lookups
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_python failed: %s", e)
            return

        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_python failed: %s", e)
            return

        if node_type in ("function_definition", "async_function_definition"):
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            decorators = self._extract_decorators_buf(node, buf)
            params = self._extract_params_buf(node, buf)
            docstring = self._extract_docstring_buf(node, buf)
            kind = SymbolKind.ASYNC_FUNCTION if node_type == "async_function_definition" else SymbolKind.FUNCTION

            is_route = any(d for d in decorators if "route" in d or "app." in d or "router." in d)
            sym_kind = SymbolKind.ROUTE if is_route else kind

            sym = SymbolNode(
                name=name,
                kind=sym_kind,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                docstring=docstring,
                language="python",
                decorators=decorators,
                params=params,
                is_exported=not name.startswith("_") or file == "__init__.py",
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

            for child in self._children(node):
                self._walk_python(child, buf, content_str, file, symbols, None)

        elif node_type == "decorated_definition":
            decorators = self._extract_decorators_buf(node, buf)
            for child in self._children(node):
                child_type = getattr(child, "type", "") if hasattr(child, "type") else ""
                if child_type in ("function_definition", "async_function_definition", "class_definition"):
                    self._walk_python(child, buf, content_str, file, symbols, parent_id)
                    if symbols:
                        symbols[-1].decorators = decorators
                else:
                    self._walk_python(child, buf, content_str, file, symbols, parent_id)

        elif node_type == "class_definition":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            docstring = self._extract_docstring_buf(node, buf)
            sym = SymbolNode(
                name=name,
                kind=SymbolKind.CLASS,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                docstring=docstring,
                language="python",
                is_exported=True,
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

            body = self._child_by_field(node, "body")
            if body:
                for child in self._children(body):
                    self._walk_python(child, buf, content_str, file, symbols, None)

        else:
            for child in self._children(node):
                self._walk_python(child, buf, content_str, file, symbols, parent_id)

    def _extract_js_ts(
        self, raw_bytes: bytes, content_str: str, file: str, lang: Lang
    ) -> list[SymbolNode]:
        """JS/TS symbols via tree-sitter."""
        symbols: list[SymbolNode] = []
        parser = get_parser(lang)
        if not parser:
            return symbols

        try:
            tree = parser.parse(raw_bytes)
            self._walk_js_ts(tree.root_node, raw_bytes, content_str, file, symbols, None)
        except Exception as e:
            _log.warning("SymbolGraph._extract_js_ts failed: %s", e)

        return symbols

    def _walk_js_ts(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_js_ts failed: %s", e)
            return

        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_js_ts failed: %s", e)
            return

        func_types = {
            "function_declaration", "function_definition",
            "method_definition", "arrow_function",
            "generator_function_declaration",
        }
        class_types = {"class_declaration", "class_definition"}
        export_types = {"export_statement", "export_specifier"}

        if node_type in func_types:
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            decorators = self._extract_decorators_buf(node, buf)
            params = self._extract_params_buf(node, buf)
            kind = SymbolKind.ASYNC_FUNCTION if node_type == "arrow_function" else SymbolKind.FUNCTION

            is_route = any(d for d in decorators if "route" in d or "app." in d or "router." in d)
            sym_kind = SymbolKind.ROUTE if is_route else kind

            sym = SymbolNode(
                name=name,
                kind=sym_kind,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                language="typescript" if file.endswith((".ts", ".tsx")) else "javascript",
                decorators=decorators,
                params=params,
                is_exported=False,
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            for child in self._children(node):
                self._walk_js_ts(child, buf, content_str, file, symbols, None)

        elif node_type in class_types:
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name,
                kind=SymbolKind.CLASS,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                language="typescript" if file.endswith((".ts", ".tsx")) else "javascript",
                is_exported=False,
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            body = self._child_by_field(node, "body")
            if body:
                for child in self._children(body):
                    self._walk_js_ts(child, buf, content_str, file, symbols, None)

        elif node_type in export_types:
            for child in self._children(node):
                self._walk_js_ts(child, buf, content_str, file, symbols, parent_id)

        else:
            for child in self._children(node):
                self._walk_js_ts(child, buf, content_str, file, symbols, parent_id)

    def _extract_rust(
        self, raw_bytes: bytes, content_str: str, file: str
    ) -> list[SymbolNode]:
        symbols: list[SymbolNode] = []
        parser = get_parser(Lang.RUST)
        if not parser:
            return symbols
        try:
            tree = parser.parse(raw_bytes)
            self._walk_rust(tree.root_node, raw_bytes, content_str, file, symbols, None)
        except Exception as e:
            _log.warning("SymbolGraph._extract_rust failed: %s", e)
        return symbols

    def _walk_rust(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_rust failed: %s", e)
            return

        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_rust failed: %s", e)
            return

        # Track route attribute macros on adjacent items
        pending_route: tuple[str, str] | None = None
        if node_type == "attribute_item":
            attr_text = self._node_text_buf(node, buf)
            rm = _RUST_ROUTE_ATTR_RE.search(attr_text)
            if rm:
                pending_route = (rm.group(1).upper(), rm.group(2))
            for child in self._children(node):
                self._walk_rust(child, buf, content_str, file, symbols, parent_id)
            return

        if node_type == "function_item":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            params = self._extract_params_buf(node, buf)

            is_route = pending_route is not None
            kind = SymbolKind.ROUTE if is_route else SymbolKind.FUNCTION

            sym = SymbolNode(
                name=name,
                kind=kind,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                language="rust",
                params=params,
                hash=_node_hash_buf(node, buf),
            )
            if is_route and pending_route:
                sym.decorators = [f"#[{pending_route[0].lower()}(\"{pending_route[1]}\")]"]
            symbols.append(sym)

        elif node_type == "struct_item":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name,
                kind=SymbolKind.CLASS,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                language="rust",
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "enum_item":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name,
                kind=SymbolKind.CLASS,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                language="rust",
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "impl_item":
            type_node = self._child_by_field(node, "type")
            trait_node = self._child_by_field(node, "trait")
            name = ""
            if trait_node:
                name = f"impl {self._node_text_buf(trait_node, buf)} for {self._node_text_buf(type_node, buf)}" if type_node else f"impl {self._node_text_buf(trait_node, buf)}"
            elif type_node:
                name = f"impl {self._node_text_buf(type_node, buf)}"
            if name:
                sym = SymbolNode(
                    name=name,
                    kind=SymbolKind.CLASS,
                    file=file,
                    line=start_line,
                    end_line=end_line,
                    parent_id=parent_id,
                    language="rust",
                    hash=_node_hash_buf(node, buf),
                )
                symbols.append(sym)
                body = self._child_by_field(node, "body")
                if body:
                    for child in self._children(body):
                        self._walk_rust(child, buf, content_str, file, symbols, None)

        elif node_type == "trait_item":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=f"trait {name}",
                kind=SymbolKind.CLASS,
                file=file,
                line=start_line,
                end_line=end_line,
                parent_id=parent_id,
                language="rust",
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        else:
            for child in self._children(node):
                self._walk_rust(child, buf, content_str, file, symbols, parent_id)

    def _extract_svelte(
        self, raw_bytes: bytes, content_str: str, file: str
    ) -> list[SymbolNode]:
        symbols: list[SymbolNode] = []
        parser = get_parser(Lang.SVELTE)
        if not parser:
            return symbols
        try:
            tree = parser.parse(raw_bytes)
            self._walk_svelte(tree.root_node, raw_bytes, content_str, file, symbols, None)
        except Exception as e:
            _log.warning("SymbolGraph._extract_svelte failed: %s", e)
        return symbols

    def _walk_svelte(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_svelte failed: %s", e)
            return

        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_svelte failed: %s", e)
            return

        # Svelte <script> tag contains JavaScript/TypeScript — reuse JS walker
        if node_type == "script_element":
            raw_tag = self._node_text_buf(node, buf)
            _SVELTE_SCRIPT_RE.match(raw_tag)
            has_ts = "ts" in raw_tag[:80] or "lang=\"ts\"" in raw_tag[:80] or "lang='ts'" in raw_tag[:80]
            js_lang = Lang.TYPESCRIPT if has_ts else Lang.JAVASCRIPT
            js_parser = get_parser(js_lang)
            if js_parser:
                inner_text = raw_tag
                inner_bytes = inner_text.encode("utf-8")
                try:
                    js_tree = js_parser.parse(inner_bytes)
                    self._walk_js_ts(js_tree.root_node, inner_bytes, inner_text, file, symbols, parent_id)
                except Exception as e:
                    _log.warning("SymbolGraph._walk_svelte failed: %s", e)
            return

        # Component tags (capitalized) → custom components referenced
        if node_type == "element":
            tag_text = self._node_text_buf(node, buf).split()[0] if self._node_text_buf(node, buf) else ""
            if tag_text and tag_text[0].isupper():
                sym = SymbolNode(
                    name=tag_text,
                    kind=SymbolKind.CLASS,
                    file=file,
                    line=start_line,
                    end_line=end_line,
                    parent_id=parent_id,
                    language="svelte",
                    hash=_node_hash_buf(node, buf),
                )
                symbols.append(sym)

        for child in self._children(node):
            self._walk_svelte(child, buf, content_str, file, symbols, parent_id)

    # ── Java extractor ─────────────────────────────────────────────────────

    def _extract_java(
        self, raw_bytes: bytes, content_str: str, file: str
    ) -> list[SymbolNode]:
        symbols: list[SymbolNode] = []
        parser = get_parser(Lang.JAVA)
        if not parser:
            return symbols
        try:
            tree = parser.parse(raw_bytes)
            self._walk_java(tree.root_node, raw_bytes, content_str, file, symbols, None)
        except Exception as e:
            _log.warning("SymbolGraph._extract_java failed: %s", e)
        return symbols

    def _walk_java(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_java failed: %s", e)
            return
        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_java failed: %s", e)
            return

        if node_type == "class_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="java", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            body = self._child_by_field(node, "body")
            if body:
                for child in self._children(body):
                    self._walk_java(child, buf, content_str, file, symbols, None)

        elif node_type == "interface_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=f"interface {name}", kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="java", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "annotation_type_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=f"@interface {name}", kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="java", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "method_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            decorators = self._extract_decorators_buf(node, buf)
            is_route = any("GetMapping" in d or "PostMapping" in d or "RequestMapping" in d or
                          "PutMapping" in d or "DeleteMapping" in d or "PatchMapping" in d
                          for d in decorators)
            kind = SymbolKind.ROUTE if is_route else SymbolKind.FUNCTION
            sym = SymbolNode(
                name=name, kind=kind, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="java", decorators=decorators,
                hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            for child in self._children(node):
                self._walk_java(child, buf, content_str, file, symbols, None)

        elif node_type == "enum_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=f"enum {name}", kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="java", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "record_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=f"record {name}", kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="java", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        else:
            for child in self._children(node):
                self._walk_java(child, buf, content_str, file, symbols, parent_id)

    # ── Go extractor ───────────────────────────────────────────────────────

    def _extract_go(
        self, raw_bytes: bytes, content_str: str, file: str
    ) -> list[SymbolNode]:
        symbols: list[SymbolNode] = []
        parser = get_parser(Lang.GO)
        if not parser:
            return symbols
        try:
            tree = parser.parse(raw_bytes)
            self._walk_go(tree.root_node, raw_bytes, content_str, file, symbols, None)
        except Exception as e:
            _log.warning("SymbolGraph._extract_go failed: %s", e)
        return symbols

    def _walk_go(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_go failed: %s", e)
            return
        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_go failed: %s", e)
            return

        if node_type == "function_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.FUNCTION, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="go", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "method_declaration":
            name_node = self._child_by_field(node, "name")
            receiver_node = self._child_by_field(node, "receiver")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            if receiver_node:
                recv_text = self._node_text_buf(receiver_node, buf)
                name = f"({recv_text}).{name}"
            sym = SymbolNode(
                name=name, kind=SymbolKind.METHOD, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="go", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "type_declaration":
            for child in self._children(node):
                self._walk_go(child, buf, content_str, file, symbols, parent_id)

        elif node_type == "type_spec":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            type_node = self._child_by_field(node, "type")
            sub_kind = SymbolKind.CLASS
            if type_node:
                ttype = getattr(type_node, "type", "")
                if ttype == "struct_type":
                    sub_kind = SymbolKind.CLASS
                elif ttype == "interface_type":
                    name = f"interface {name}"
            sym = SymbolNode(
                name=name, kind=sub_kind, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="go", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            if type_node:
                for child in self._children(type_node):
                    self._walk_go(child, buf, content_str, file, symbols, None)

        else:
            for child in self._children(node):
                self._walk_go(child, buf, content_str, file, symbols, parent_id)

    # ── C/C++ extractor ────────────────────────────────────────────────────

    def _extract_c_cpp(
        self, raw_bytes: bytes, content_str: str, file: str, lang: Lang
    ) -> list[SymbolNode]:
        symbols: list[SymbolNode] = []
        parser = get_parser(lang)
        if not parser:
            return symbols
        try:
            tree = parser.parse(raw_bytes)
            self._walk_c_cpp(tree.root_node, raw_bytes, content_str, file, symbols, None, lang)
        except Exception as e:
            _log.warning("SymbolGraph._extract_c_cpp failed: %s", e)
        return symbols

    def _walk_c_cpp(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None,
        lang: Lang
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_c_cpp failed: %s", e)
            return
        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_c_cpp failed: %s", e)
            return

        lang_str = "c" if lang == Lang.C else "cpp"

        if node_type == "function_definition":
            decl = self._child_by_field(node, "declarator")
            name = ""
            if decl:
                name_node = self._child_by_field(decl, "declarator") if hasattr(decl, "child_by_field_name") else None
                if not name_node:
                    name_node = self._child_by_field(decl, "name")
                if name_node:
                    name = self._node_text_buf(name_node, buf)
            if not name:
                name = self._node_text_buf(node, buf)[:30]
            sym = SymbolNode(
                name=name, kind=SymbolKind.FUNCTION, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language=lang_str, hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "struct_specifier" and lang == Lang.CPP:
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language=lang_str, hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        elif node_type == "class_specifier":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language=lang_str, hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            body = self._child_by_field(node, "body")
            if body:
                for child in self._children(body):
                    self._walk_c_cpp(child, buf, content_str, file, symbols, None, lang)

        elif node_type == "namespace_definition":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=f"namespace {name}", kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language=lang_str, hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)

        else:
            for child in self._children(node):
                self._walk_c_cpp(child, buf, content_str, file, symbols, parent_id, lang)

    def _extract_swift(
        self, raw_bytes: bytes, content_str: str, file: str
    ) -> list[SymbolNode]:
        symbols: list[SymbolNode] = []
        parser = get_parser(Lang.SWIFT)
        if not parser:
            return symbols
        try:
            tree = parser.parse(raw_bytes)
            self._walk_swift(tree.root_node, raw_bytes, content_str, file, symbols, None)
        except Exception as e:
            _log.warning("SymbolGraph._extract_swift failed: %s", e)
        return symbols

    def _walk_swift(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_swift failed: %s", e)
            return
        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_swift failed: %s", e)
            return

        if node_type == "import_declaration":
            # Skip — imports are handled by scanner, not needed as symbols
            pass

        elif node_type == "class_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="swift", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            body = self._child_by_field(node, "body")
            if body:
                for child in self._children(body):
                    self._walk_swift(child, buf, content_str, file, symbols, sym.id)

        elif node_type == "function_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.FUNCTION, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="swift", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            for child in self._children(node):
                self._walk_swift(child, buf, content_str, file, symbols, sym.id)

        elif node_type == "protocol_declaration":
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            symbols.append(
                SymbolNode(
                    name=f"protocol {name}", kind=SymbolKind.CLASS, file=file,
                    line=start_line, end_line=end_line, parent_id=parent_id,
                    language="swift", hash=_node_hash_buf(node, buf),
                )
            )

        else:
            for child in self._children(node):
                self._walk_swift(child, buf, content_str, file, symbols, parent_id)

    # ── Ruby extractor ───────────────────────────────────────────────────────

    def _extract_ruby(
        self, raw_bytes: bytes, content_str: str, file: str
    ) -> list[SymbolNode]:
        symbols: list[SymbolNode] = []
        parser = get_parser(Lang.RUBY)
        if not parser:
            return symbols
        try:
            tree = parser.parse(raw_bytes)
            self._walk_ruby(tree.root_node, raw_bytes, content_str, file, symbols, None)
        except Exception as e:
            _log.warning("SymbolGraph._extract_ruby failed: %s", e)
        return symbols

    def _walk_ruby(
        self, node: Any, raw_bytes: bytes, content_str: str,
        file: str, symbols: list[SymbolNode], parent_id: int | None
    ) -> None:
        buf = raw_bytes
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_ruby failed: %s", e)
            return
        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_ruby failed: %s", e)
            return

        if node_type == "call":
            name = ""
            for c in self._children(node):
                if c.type == "identifier":
                    name = self._node_text_buf(c, buf)
                    break
            if name in ("require", "require_relative", "load", "include", "extend", "prepend"):
                arg = ""
                for c in self._children(node):
                    if c.type == "argument_list":
                        for a in self._children(c):
                            if a.type == "string":
                                arg = self._node_text_buf(a, buf).strip('"\'')
                                break
                if arg:
                    # Skip — imports handled by scanner
                    pass

        elif node_type == "method":
            name_node = None
            for c in self._children(node):
                if c.type == "identifier":
                    name_node = c
                    break
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.FUNCTION, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="ruby", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            body = None
            for c in self._children(node):
                if c.type == "body_statement":
                    body = c
                    break
            if body:
                for child in self._children(body):
                    self._walk_ruby(child, buf, content_str, file, symbols, sym.id)

        elif node_type == "class":
            name_node = None
            for c in self._children(node):
                if c.type == "constant":
                    name_node = c
                    break
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=name, kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="ruby", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            for c in self._children(node):
                if c.type == "body_statement":
                    for child in self._children(c):
                        self._walk_ruby(child, buf, content_str, file, symbols, sym.id)

        elif node_type in ("module", "singleton_class"):
            name_node = None
            for c in self._children(node):
                if c.type == "constant":
                    name_node = c
                    break
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
            sym = SymbolNode(
                name=f"module {name}" if node_type == "module" else name,
                kind=SymbolKind.CLASS, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language="ruby", hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            for c in self._children(node):
                if c.type == "body_statement":
                    for child in self._children(c):
                        self._walk_ruby(child, buf, content_str, file, symbols, sym.id)

        else:
            for child in self._children(node):
                self._walk_ruby(child, buf, content_str, file, symbols, parent_id)

    def _extract_generic_ts(
        self, raw_bytes: bytes, content_str: str, file: str, lang: Lang,
        function_types: set[str] | None = None,
        method_types: set[str] | None = None,
        class_types: set[str] | None = None,
    ) -> list[SymbolNode]:
        """Generic tree-sitter symbol extractor for languages without custom walkers."""
        symbols: list[SymbolNode] = []
        parser = get_parser(lang)
        if not parser:
            return []
        try:
            tree = parser.parse(raw_bytes)
            self._walk_generic(tree.root_node, raw_bytes, file, lang, symbols, None,
                               function_types or set(), method_types or set(), class_types or set())
        except Exception as e:
            _log.warning("SymbolGraph._extract_generic_ts failed: %s", e)
        return symbols

    def _walk_generic(
        self, node: Any, buf: bytes, file: str, lang: Lang,
        symbols: list[SymbolNode], parent_id: int | None,
        function_types: set[str], method_types: set[str], class_types: set[str],
    ) -> None:
        try:
            node_type = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_generic failed: %s", e)
            return
        try:
            start_line = node.start_point[0] + 1 if node.start_point else 0
            end_line = node.end_point[0] + 1 if node.end_point else 0
        except Exception as e:
            _log.warning("SymbolGraph._walk_generic failed: %s", e)
            return

        kind = None
        if node_type in function_types:
            kind = SymbolKind.FUNCTION
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
        elif node_type in method_types:
            kind = SymbolKind.FUNCTION
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"
        elif node_type in class_types:
            kind = SymbolKind.CLASS
            name_node = self._child_by_field(node, "name")
            name = self._node_text_buf(name_node, buf) if name_node else "anon"

        if kind:
            lang_str = lang.value if hasattr(lang, "value") else str(lang)
            sym = SymbolNode(
                name=name, kind=kind, file=file,
                line=start_line, end_line=end_line, parent_id=parent_id,
                language=lang_str, hash=_node_hash_buf(node, buf),
            )
            symbols.append(sym)
            for child in self._children(node):
                self._walk_generic(child, buf, file, lang, symbols, sym.id,
                                   function_types, method_types, class_types)
            return

        for child in self._children(node):
            self._walk_generic(child, buf, file, lang, symbols, parent_id,
                               function_types, method_types, class_types)

    # ── Internal: Tree-sitter helpers ──────────────────────────────────────

    def _children(self, node: Any) -> list[Any]:
        try:
            return list(node.children) if hasattr(node, "children") else []
        except Exception as e:
            _log.warning("SymbolGraph._children failed: %s", e)
            return []

    def _child_by_field(self, node: Any, field_name: str) -> Any | None:
        try:
            return node.child_by_field_name(field_name) if hasattr(node, "child_by_field_name") else None
        except Exception as e:
            _log.warning("SymbolGraph._child_by_field failed: %s", e)
            return None

    def _node_text_buf(self, node: Any, buf: bytes) -> str:
        """Extract text from a tree-sitter node using the raw byte buffer."""
        try:
            if hasattr(node, "start_byte") and hasattr(node, "end_byte"):
                return buf[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
        except Exception as e:
            _log.warning("SymbolGraph._node_text_buf failed: %s", e)
        return ""

    def _extract_decorators_buf(self, node: Any, buf: bytes) -> list[str]:
        decorators: list[str] = []
        decorator = self._child_by_field(node, "decorator")
        if decorator:
            text = self._node_text_buf(decorator, buf)
            if text:
                decorators.append(text.strip())
        for child in self._children(node):
            try:
                if getattr(child, "type", "") == "decorator":
                    text = self._node_text_buf(child, buf)
                    if text:
                        decorators.append(text.strip())
            except Exception as e:
                _log.warning("SymbolGraph._extract_decorators_buf failed: %s", e)
        return decorators

    def _extract_params_buf(self, node: Any, buf: bytes) -> list[str]:
        params_node = self._child_by_field(node, "parameters")
        if not params_node:
            return []
        text = self._node_text_buf(params_node, buf)
        if not text:
            return []
        import re
        return [
            p.strip() for p in re.split(r"[,:]", text.strip("()"))
            if p.strip() and not p.strip().startswith("*")
        ]

    def _extract_docstring_buf(self, node: Any, buf: bytes) -> str:
        body = self._child_by_field(node, "body")
        if not body:
            return ""
        children = self._children(body)
        if not children:
            return ""
        first = children[0]
        try:
            if hasattr(first, "type") and first.type in ("expression_statement", "string"):
                return self._node_text_buf(first, buf)[:200]
        except Exception as e:
            _log.warning("SymbolGraph._extract_docstring_buf failed: %s", e)
        return ""

    # ── Internal: SQLite helpers ───────────────────────────────────────────

    def _insert_symbol(self, conn: sqlite3.Connection, sym: SymbolNode, file: str) -> None:
        content_hash = sym.hash or hashlib.md5(f"{sym.name}{sym.line}{sym.kind}".encode()).hexdigest()[:12]
        conn.execute(
            """INSERT OR IGNORE INTO symbols
               (name, kind, file, line, end_line, parent_id, docstring, language, hash, decorators, params, is_exported)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sym.name,
                sym.kind,
                file,
                sym.line,
                sym.end_line,
                sym.parent_id,
                sym.docstring,
                sym.language,
                content_hash,
                ",".join(sym.decorators),
                ",".join(sym.params),
                1 if sym.is_exported else 0,
            ),
        )

    def _get_symbols_in_file(self, conn: sqlite3.Connection, file: str) -> list[SymbolNode]:
        cur = conn.execute(
            "SELECT * FROM symbols WHERE file = ? ORDER BY line", (file,)
        )
        return [self._row_to_symbol(r) for r in cur.fetchall()]

    def _get_symbol_by_id(self, sid: int) -> SymbolNode | None:
        conn = self._get_conn()
        cur = conn.execute("SELECT * FROM symbols WHERE id = ?", (sid,))
        row = cur.fetchone()
        return self._row_to_symbol(row) if row else None

    def _row_to_symbol(self, row: sqlite3.Row) -> SymbolNode:
        return SymbolNode(
            id=row[0],
            name=row[1],
            kind=row[2],
            file=row[3],
            line=row[4],
            end_line=row[5],
            parent_id=row[6],
            docstring=row[7] or "",
            language=row[8],
            hash=row[9] or "",
            decorators=row[10].split(",") if row[10] else [],
            params=row[11].split(",") if row[11] else [],
            is_exported=bool(row[12]),
        )

    def _build_edges(self, conn: sqlite3.Connection, files: list[FileInfo]) -> None:
        """Build symbol-level call/reference edges by scanning ASTs."""
        for fi in files:
            abs_path = self.root / fi.path
            if not abs_path.exists():
                continue
            content = abs_path.read_text(encoding="utf-8", errors="ignore")
            file_symbols = self._get_symbols_in_file(conn, fi.path)
            if not file_symbols:
                continue

            refs = self._find_references(content, fi.language)
            for sym in file_symbols:
                for ref_name in refs:
                    target = self._find_local_symbol(conn, ref_name, fi.path, sym.line)
                    if target and target.id != sym.id:
                        try:
                            conn.execute(
                                "INSERT OR IGNORE INTO edges (source_id, target_id, kind) VALUES (?, ?, ?)",
                                (sym.id, target.id, "calls"),
                            )
                        except Exception as e:
                            _log.warning("SymbolGraph._build_edges failed: %s", e)

    def _find_references(self, content: str, lang: Lang) -> set[str]:
        """Extract referenced names from source content using AST."""
        import ast

        refs: set[str] = set()
        if lang == Lang.PYTHON:
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        refs.add(node.func.id)
                    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                        refs.add(node.func.attr)
                    elif isinstance(node, ast.Name):
                        refs.add(node.id)
            except SyntaxError:
                pass
        else:
            parser = get_parser(lang)
            if parser:
                try:
                    tree = parser.parse(content.encode("utf-8"))
                    self._walk_calls(tree.root_node, refs)
                except Exception as e:
                    _log.warning("SymbolGraph._find_references failed: %s", e)

        return refs

    def _walk_calls(self, node: Any, refs: set[str]) -> None:
        """Walk a tree-sitter AST extracting call target names."""
        try:
            ntype = node.type if hasattr(node, "type") else ""
        except Exception as e:
            _log.warning("SymbolGraph._walk_calls failed: %s", e)
            return

        # Common call-like node types across grammars
        if ntype in ("call_expression", "method_invocation",
                     "function_call_expression", "invocation_expression"):
            fn = self._child_by_field(node, "function") or self._child_by_field(node, "name")
            if fn:
                try:
                    text = fn.text if hasattr(fn, "text") else b""
                    if isinstance(text, bytes):
                        text = text.decode("utf-8", errors="replace")
                    name = str(text).split(".")[-1].split("::")[-1]
                    if name and name.isidentifier():
                        refs.add(name)
                except Exception as e:
                    _log.warning("SymbolGraph._walk_calls failed: %s", e)

        # Ruby: call node has method field
        elif ntype == "call":
            fn = self._child_by_field(node, "method")
            if fn:
                try:
                    text = fn.text if hasattr(fn, "text") else b""
                    if isinstance(text, bytes):
                        text = text.decode("utf-8", errors="replace")
                    name = str(text)
                    if name and name.isidentifier():
                        refs.add(name)
                except Exception as e:
                    _log.warning("SymbolGraph._walk_calls failed: %s", e)

        for child in (node.children if hasattr(node, "children") else []):
            self._walk_calls(child, refs)

    def _find_local_symbol(
        self, conn: sqlite3.Connection, name: str, file: str, near_line: int
    ) -> SymbolNode | None:
        """Find a symbol by name in the same file, preferring the one closest to near_line."""
        cur = conn.execute(
            "SELECT * FROM symbols WHERE file = ? AND name = ? ORDER BY ABS(line - ?) LIMIT 1",
            (file, name, near_line),
        )
        row = cur.fetchone()
        return self._row_to_symbol(row) if row else None

    def __enter__(self) -> SymbolGraph:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ── Utility ─────────────────────────────────────────────────────────────────────


def _content_hash(content: str) -> str:
    return hashlib.md5(content.encode("utf-8")).hexdigest()[:12]


def _node_hash_buf(node: Any, buf: bytes) -> str:
    """Hash the node's source content from a raw byte buffer."""
    try:
        if hasattr(node, "start_byte") and hasattr(node, "end_byte"):
            return hashlib.md5(buf[node.start_byte : node.end_byte]).hexdigest()[:12]
    except Exception as e:
        _log.debug("_node_hash_buf failed: %s", e)
    return hashlib.md5(str(id(node)).encode()).hexdigest()[:12]
