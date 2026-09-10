"""
Brain file scanner.

Walks the project directory. Discovers all source files.
Extracts structured data from each: imports, exports, functions, classes, routes.

Parsing strategy:
  All code languages (Python, JS/TS, Rust, Svelte, Java, Go, C/C++, Swift, Ruby,
  PHP, C#, Kotlin, Dart, Bash, CSS, SQL):
    tree-sitter AST (accurate, structural)
  Config/data languages (JSON, YAML):
    stdlib parsing (fit-for-purpose)
  HTML:
    stdlib html.parser

Output per file (FileInfo):
  path, language, size, imports, exports, functions, classes, is_entry_point, purpose
"""
from __future__ import annotations

import ast as py_ast
import hashlib
import logging
import os
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from patchi.core.brain.file_corpus import FileCorpus
from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS as _LANG_IGNORE_DIRS
from patchi.core.brain.languages import Lang, detect_language, get_parser

# ── Data model ─────────────────────────────────────────────────────────────────


_log = logging.getLogger("patchi.brain.scanner")


@dataclass
class ImportInfo:
    source: str  # e.g. "os", "./auth", "@/components/Button"
    names: list[str]  # e.g. ["path", "getcwd"] or ["default"] for default import
    is_relative: bool
    line: int = 0


@dataclass
class FunctionInfo:
    name: str
    line: int
    is_async: bool = False
    params: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)


@dataclass
class ClassInfo:
    name: str
    line: int
    bases: list[str] = field(default_factory=list)


@dataclass
class FileInfo:
    path: str  # relative to project root
    language: Lang
    size_bytes: int
    lines: int
    imports: list[ImportInfo] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    classes: list[ClassInfo] = field(default_factory=list)
    is_entry_point: bool = False
    purpose: str = ""  # one-sentence plain English
    error: str | None = None  # if parsing failed

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "language": self.language.value,
            "size_bytes": self.size_bytes,
            "lines": self.lines,
            "imports": [
                {"source": i.source, "names": i.names, "is_relative": i.is_relative, "line": i.line}
                for i in self.imports
            ],
            "exports": self.exports,
            "functions": [
                {
                    "name": f.name,
                    "line": f.line,
                    "is_async": f.is_async,
                    "params": f.params,
                    "decorators": f.decorators,
                }
                for f in self.functions
            ],
            "classes": [{"name": c.name, "line": c.line, "bases": c.bases} for c in self.classes],
            "is_entry_point": self.is_entry_point,
            "purpose": self.purpose,
            "error": self.error,
        }


# ── Shared dispatch ────────────────────────────────────────────────────────────


def _parse_by_language(source: str, info: FileInfo, lang: Lang) -> None:
    """Dispatch to the appropriate language parser."""
    if lang == Lang.PYTHON:
        _parse_python(source, info)
    elif lang in (Lang.JAVASCRIPT, Lang.TYPESCRIPT):
        _parse_js_ts(source, lang, info)
    elif lang == Lang.RUST:
        _parse_rust(source, info)
    elif lang == Lang.SVELTE:
        _parse_svelte(source, info)
    elif lang == Lang.JAVA:
        _parse_java(source, info)
    elif lang == Lang.GO:
        _parse_go(source, info)
    elif lang in (Lang.C, Lang.CPP):
        _parse_c_cpp(source, info)
    elif lang == Lang.SWIFT:
        _parse_swift(source, info)
    elif lang == Lang.RUBY:
        _parse_ruby(source, info)
    elif lang == Lang.JSON:
        _parse_json(source, info)
    elif lang == Lang.YAML:
        _parse_yaml(source, info)
    elif lang == Lang.PHP:
        _parse_php(source, info)
    elif lang == Lang.C_SHARP:
        _parse_csharp(source, info)
    elif lang == Lang.KOTLIN:
        _parse_kotlin(source, info)
    elif lang == Lang.DART:
        _parse_dart(source, info)
    elif lang == Lang.BASH:
        _parse_bash(source, info)
    elif lang == Lang.CSS:
        _parse_css(source, info)
    elif lang == Lang.SQL:
        _parse_sql(source, info)
    elif lang == Lang.HTML:
        _parse_html(source, info)
    elif lang == Lang.SCALA:
        # No Scala grammar on PyPI yet -- regex is the intentional, permanent
        # choice here (not a placeholder), per the language expansion plan.
        _parse_scala_regex(source, info)
    else:
        _parse_generic(source, info)


# ── Default ignore patterns ────────────────────────────────────────────────────

DEFAULT_IGNORE_DIRS = _LANG_IGNORE_DIRS

DEFAULT_IGNORE_EXTS = {
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dll",
    ".dylib",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".wav",
    ".ogg",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".7z",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".lock",  # package-lock.json, yarn.lock, etc. — too noisy
    ".map",  # source maps
    ".min.js",  # minified — detected via endswith below
}

MAX_FILE_SIZE = 500 * 1024  # 500KB — skip files larger than this


# ── Parallel scanning support ──────────────────────────────────────────────────

_file_hash_cache: dict[str, str] = {}  # rel_path -> content hash
_file_info_cache: dict[str, dict] = {}  # rel_path -> serialized FileInfo dict


def _load_ast_cache(root: Path) -> None:
    """Load persisted AST hash cache from .patchi/ast_cache.json."""
    global _file_hash_cache
    cache_file = root / ".patchi" / "ast_cache.json"
    if cache_file.exists():
        try:
            import json

            with open(cache_file, encoding="utf-8") as f:
                loaded = json.load(f)
            _file_hash_cache.clear()
            _file_hash_cache.update(loaded)
        except (json.JSONDecodeError, OSError):
            pass


def _save_ast_cache(root: Path) -> None:
    """Persist AST hash cache to .patchi/ast_cache.json."""
    cache_file = root / ".patchi" / "ast_cache.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        import json

        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(_file_hash_cache, f)
    except OSError:
        pass


def _load_file_info_cache(root: Path) -> None:
    """Load persisted file info cache from .patchi/file_info_cache.json."""
    global _file_info_cache
    cache_file = root / ".patchi" / "file_info_cache.json"
    if cache_file.exists():
        try:
            import json

            with open(cache_file, encoding="utf-8") as f:
                loaded = json.load(f)
            _file_info_cache.clear()
            _file_info_cache.update(loaded)
            # Backfill mtime for old cache entries (first run after upgrade)
            backfilled = 0
            for rel, entry in _file_info_cache.items():
                if "mtime" not in entry:
                    try:
                        full = root / rel
                        st = full.stat()
                        entry["mtime"] = st.st_mtime
                        entry["size_bytes"] = st.st_size
                        backfilled += 1
                    except OSError:
                        pass
            if backfilled:
                _save_file_info_cache(root)
        except (json.JSONDecodeError, OSError):
            pass


def _save_file_info_cache(root: Path) -> None:
    """Persist file info cache to .patchi/file_info_cache.json."""
    cache_file = root / ".patchi" / "file_info_cache.json"
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        import json

        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(_file_info_cache, f)
    except OSError:
        pass


def _file_content_hash(path: Path) -> str:
    """Compute MD5 hash of file content for caching."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan_single_file(args: tuple[str, str]) -> dict:
    """
    Standalone worker function for parallel scanning.
    Args: (root_str, file_path_str)
    Returns: serialized FileInfo dict
    """
    root_str, file_path_str = args
    root = Path(root_str)
    path = Path(file_path_str)
    rel_path = path.relative_to(root).as_posix()
    lang = detect_language(path)

    try:
        stat = path.stat()
        if stat.st_size > MAX_FILE_SIZE:
            return {
                "path": rel_path,
                "language": lang.value,
                "size_bytes": stat.st_size,
                "lines": 0,
                "error": f"File too large ({stat.st_size // 1024}KB), skipped",
            }

        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {
            "path": rel_path,
            "language": lang.value,
            "size_bytes": 0,
            "lines": 0,
            "error": str(e),
        }

    lines = source.rstrip("\n").count("\n") + 1 if source.strip() else 0
    size = len(source.encode("utf-8"))

    info = FileInfo(path=rel_path, language=lang, size_bytes=size, lines=lines)

    try:
        _parse_by_language(source, info, lang)
    except Exception as e:
        info.error = f"Parse error: {e}"

    info.is_entry_point = _is_entry_point(path, info)
    info.purpose = _infer_purpose(path, info)

    return info.to_dict()


# ── Scanner ────────────────────────────────────────────────────────────────────


class FileScanner:
    """
    Walks a project directory and parses all source files.

    Usage:
        scanner = FileScanner(project_root)
        files = scanner.scan()           # scan all
        files = scanner.scan("src/auth") # targeted scan
    """

    def __init__(
        self,
        root: Path,
        ignore_dirs: set[str] | None = None,
        ignore_paths: list[str] | None = None,
        max_depth: int | None = None,
        max_workers: int | None = None,
        corpus: FileCorpus | None = None,
    ):
        self.root = root
        self.ignore_dirs = (ignore_dirs or set()) | DEFAULT_IGNORE_DIRS
        self.ignore_paths = set(ignore_paths or [])
        self.max_depth = max_depth
        self.max_workers = max_workers
        self._corpus = corpus

    def discover(self, area: str | None = None) -> list[Path]:
        """
        Return all source file paths under area (relative to root),
        or the full project if area is None.
        Applies ignore rules. Does not parse.
        Uses FileCorpus when available for full-project scans.
        """
        if area is None and self._corpus is not None:
            return self._discover_from_corpus()

        start = self.root
        if area:
            candidate = self.root / area
            if candidate.exists():
                start = candidate

        paths: list[Path] = []
        base_depth = len(start.parts)

        for dirpath, dirnames, filenames in os.walk(start):
            current = Path(dirpath)

            # Depth limit
            if self.max_depth is not None:
                depth = len(current.parts) - base_depth
                if depth >= self.max_depth:
                    dirnames.clear()
                    continue

            # Prune ignored dirs
            def _safe_relative(p: Path) -> str | None:
                try:
                    return p.relative_to(self.root).as_posix()
                except ValueError:
                    return None

            dirnames[:] = [
                d
                for d in dirnames
                if d not in self.ignore_dirs
                and (_safe_relative(current / d) not in self.ignore_paths)
            ]

            for fname in filenames:
                fpath = current / fname
                try:
                    rel = fpath.relative_to(self.root)
                except ValueError:
                    continue

                # Skip ignored paths
                if any(rel.as_posix().startswith(p) for p in self.ignore_paths):
                    continue

                # Skip minified files
                if fname.endswith(".min.js") or fname.endswith(".min.css"):
                    continue

                # Skip by extension
                if fpath.suffix.lower() in DEFAULT_IGNORE_EXTS:
                    continue

                # Skip unknown language files
                lang = detect_language(fpath)
                if lang == Lang.UNKNOWN:
                    continue

                paths.append(fpath)

        return paths

    def _discover_from_corpus(self) -> list[Path]:
        paths: list[Path] = []
        ignore = self.ignore_paths
        for entry in self._corpus.entries.values():
            if any(entry.path.startswith(p) for p in ignore):
                continue
            fname = Path(entry.path).name
            if fname.endswith(".min.js") or fname.endswith(".min.css"):
                continue
            paths.append(self.root / entry.path)
        return paths

    def scan_file(self, path: Path, use_cache: bool = True) -> FileInfo:
        """Parse a single file and return a FileInfo.

        When use_cache is True and the file content hash matches the previous
        scan, the cached FileInfo dict is restored instead of re-parsing.
        """
        rel_path = path.relative_to(self.root).as_posix()
        lang = detect_language(path)

        # Quick-skip: files under 100 bytes are trivial — skip hash + parse
        try:
            quick_stat = path.stat()
        except OSError as e:
            return FileInfo(path=rel_path, language=lang, size_bytes=0, lines=0, error=str(e))

        if quick_stat.st_size < 100:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                source = ""
            lines = source.rstrip("\n").count("\n") + 1 if source.strip() else 0
            return FileInfo(
                path=rel_path, language=lang, size_bytes=quick_stat.st_size, lines=lines
            )

        # Incremental caching: skip re-parsing unchanged files (M-04)
        # Uses mtime+size instead of content hash for speed (stat is ~100x faster)
        if use_cache:
            try:
                cached_entry = _file_info_cache.get(rel_path)
                if cached_entry and cached_entry.get("language") == lang.value:
                    # Quick check: if mtime and size match, file is unchanged
                    cached_mtime = cached_entry.get("mtime", 0)
                    cached_size = cached_entry.get("size_bytes", 0)
                    if cached_mtime == quick_stat.st_mtime and cached_size == quick_stat.st_size:
                        return FileInfo(
                            path=cached_entry["path"],
                            language=Lang(cached_entry["language"]),
                            size_bytes=cached_entry["size_bytes"],
                            lines=cached_entry["lines"],
                            imports=[ImportInfo(**i) for i in cached_entry.get("imports", [])],
                            exports=cached_entry.get("exports", []),
                            functions=[FunctionInfo(**f) for f in cached_entry.get("functions", [])],
                            classes=[ClassInfo(**c) for c in cached_entry.get("classes", [])],
                            is_entry_point=cached_entry.get("is_entry_point", False),
                            purpose=cached_entry.get("purpose", ""),
                            error=cached_entry.get("error"),
                        )
            except OSError:
                pass

        try:
            stat = path.stat()
            if stat.st_size > MAX_FILE_SIZE:
                return FileInfo(
                    path=rel_path,
                    language=lang,
                    size_bytes=stat.st_size,
                    lines=0,
                    error=f"File too large ({stat.st_size // 1024}KB), skipped",
                )

            if self._corpus is not None:
                cached = self._corpus.read(rel_path)
                if cached is not None:
                    source = cached
                else:
                    source = path.read_text(encoding="utf-8", errors="replace")
            else:
                source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return FileInfo(path=rel_path, language=lang, size_bytes=0, lines=0, error=str(e))

        # Count lines: strip one trailing newline so "a\nb\nc\n" = 3 lines
        lines = source.rstrip("\n").count("\n") + 1 if source.strip() else 0
        size = len(source.encode("utf-8"))

        info = FileInfo(path=rel_path, language=lang, size_bytes=size, lines=lines)

        try:
            _parse_by_language(source, info, lang)
        except Exception as e:
            info.error = f"Parse error: {e}"

        # Entry point detection
        info.is_entry_point = _is_entry_point(path, info)
        # Purpose inference
        info.purpose = _infer_purpose(path, info)

        # Cache the parsed result for incremental scanning (M-04)
        if use_cache:
            try:
                stat = path.stat()
                entry = info.to_dict()
                entry["mtime"] = stat.st_mtime
                _file_info_cache[rel_path] = entry
            except OSError:
                pass

        return info

    def scan(self, area: str | None = None, on_progress: Any = None) -> list[FileInfo]:
        """
        Discover and parse all files. Returns list of FileInfo objects.
        on_progress(current, total, path) — called for each file if provided.
        Uses ProcessPoolExecutor for parallel parsing on large projects.
        """
        # Load persisted caches for unchanged file detection
        _load_file_info_cache(self.root)
        _load_ast_cache(self.root)

        # If corpus is provided and has entries, use it directly (no re-scan)
        if self._corpus and self._corpus.entries:
            paths = [Path(str(self.root / k)) for k in self._corpus.entries]
            # Skip trivially small files (< 50 bytes) — no meaningful AST
            _MIN_SIZE = 50
            results: list[FileInfo] = []
            for i, path in enumerate(paths):
                if on_progress:
                    on_progress(i + 1, len(paths), path)
                try:
                    if path.stat().st_size < _MIN_SIZE:
                        rel = path.relative_to(self.root).as_posix()
                        results.append(FileInfo(
                            path=rel,
                            language=detect_language(path),
                            size_bytes=0,
                            lines=0,
                            error="trivially small",
                        ))
                        continue
                except OSError:
                    pass
                fi = self.scan_file(path)
                results.append(fi)
            return results

        paths = self.discover(area)
        total = len(paths)

        if total == 0:
            return []

        # For small projects or when workers limited to 1, use sequential
        if total < 50 or self.max_workers == 1:
            results: list[FileInfo] = []
            for i, path in enumerate(paths):
                if on_progress:
                    on_progress(i + 1, total, path)
                fi = self.scan_file(path)
                results.append(fi)
            return results

        # Parallel scanning with hash-based caching
        root_str = str(self.root)
        work_items = []
        cached_results = []

        for path in paths:
            rel = path.relative_to(self.root).as_posix()
            try:
                content_hash = _file_content_hash(path)
                if rel in _file_hash_cache and _file_hash_cache[rel] == content_hash:
                    # File unchanged — try to use cached result
                    # (cache stores dicts, we'll deserialize later)
                    cached_results.append((rel, content_hash))
                    continue
            except OSError:
                pass
            work_items.append((root_str, str(path)))

        # Process uncached files in parallel
        parallel_results = {}
        workers = self.max_workers or min(32, (os.cpu_count() or 4) + 4)

        if work_items:
            with ProcessPoolExecutor(max_workers=workers) as executor:
                futures = {executor.submit(_scan_single_file, item): item[1] for item in work_items}
                done_count = 0
                for future in as_completed(futures):
                    done_count += 1
                    file_path_str = futures[future]
                    try:
                        result = future.result()
                        parallel_results[result["path"]] = result
                        # Update hash + info caches (M-04)
                        try:
                            rel = Path(file_path_str).relative_to(self.root).as_posix()
                            _file_hash_cache[rel] = _file_content_hash(Path(file_path_str))
                            _file_info_cache[rel] = result
                        except OSError:
                            pass
                    except Exception as e:
                        # Fallback: sequential parse of this file
                        _log.warning("FileScanner.scan failed: %s", e)
                        try:
                            p = Path(file_path_str)
                            fi = self.scan_file(p)
                            parallel_results[fi.path] = fi.to_dict()
                        except Exception as e:
                            _log.warning("FileScanner.scan failed: %s", e)
                    if on_progress:
                        on_progress(
                            done_count + len(cached_results), total, Path(file_path_str).name
                        )

        # Build final results list (preserving discover order)
        results = []
        for path in paths:
            rel = path.relative_to(self.root).as_posix()
            if rel in parallel_results:
                d = parallel_results[rel]
                fi = FileInfo(
                    path=d["path"],
                    language=Lang(d["language"]),
                    size_bytes=d["size_bytes"],
                    lines=d["lines"],
                    is_entry_point=d.get("is_entry_point", False),
                    purpose=d.get("purpose", ""),
                    error=d.get("error"),
                )
                fi.imports = [ImportInfo(**i) for i in d.get("imports", [])]
                fi.exports = d.get("exports", [])
                fi.functions = [FunctionInfo(**f) for f in d.get("functions", [])]
                fi.classes = [ClassInfo(**c) for c in d.get("classes", [])]
                results.append(fi)
            else:
                # Sequential fallback for any remaining
                fi = self.scan_file(path)
                results.append(fi)

        # Persist caches for next scan (M-04)
        try:
            _save_ast_cache(self.root)
            _save_file_info_cache(self.root)
        except Exception as e:
            _log.warning("FileScanner.scan failed: %s", e)
        return results


# ── Python parser (using stdlib ast) ──────────────────────────────────────────


def _parse_python(source: str, info: FileInfo) -> None:
    try:
        tree = py_ast.parse(source, type_comments=False)
    except SyntaxError as e:
        info.error = f"SyntaxError: {e}"
        return

    for node in py_ast.walk(tree):
        # Imports
        if isinstance(node, py_ast.Import):
            for alias in node.names:
                info.imports.append(
                    ImportInfo(
                        source=alias.name,
                        names=[alias.asname or alias.name.split(".")[0]],
                        is_relative=False,
                        line=node.lineno,
                    )
                )
        elif isinstance(node, py_ast.ImportFrom):
            module = node.module or ""
            names = [a.name for a in node.names]
            info.imports.append(
                ImportInfo(
                    source=("." * (node.level or 0)) + module,
                    names=names,
                    is_relative=(node.level or 0) > 0,
                    line=node.lineno,
                )
            )

        # Functions
        elif isinstance(node, (py_ast.FunctionDef, py_ast.AsyncFunctionDef)):
            if isinstance(node, py_ast.AsyncFunctionDef) or _is_top_or_class(node, tree):
                decos = [_deco_name(d) for d in node.decorator_list]
                params = [a.arg for a in node.args.args]
                info.functions.append(
                    FunctionInfo(
                        name=node.name,
                        line=node.lineno,
                        is_async=isinstance(node, py_ast.AsyncFunctionDef),
                        params=params,
                        decorators=decos,
                    )
                )

        # Classes
        elif isinstance(node, py_ast.ClassDef):
            bases = [_name_of(b) for b in node.bases]
            info.classes.append(
                ClassInfo(
                    name=node.name,
                    line=node.lineno,
                    bases=bases,
                )
            )

        # Module-level __all__ → exports
        elif isinstance(node, py_ast.Assign) and any(
            isinstance(t, py_ast.Name) and t.id == "__all__" for t in node.targets
        ):
            if isinstance(node.value, (py_ast.List, py_ast.Tuple)):
                info.exports = [
                    elt.value
                    for elt in node.value.elts
                    if isinstance(elt, py_ast.Constant) and isinstance(elt.value, str)
                ]


def _is_top_or_class(node: py_ast.AST, tree: py_ast.Module) -> bool:
    """True if the function is at module or class level (not nested in another function)."""
    return True  # simplified — walk always gives us all defs, filtering by nesting is complex


def _deco_name(node: py_ast.expr) -> str:
    if isinstance(node, py_ast.Name):
        return node.id
    if isinstance(node, py_ast.Attribute):
        return f"{_name_of(node.value)}.{node.attr}"
    if isinstance(node, py_ast.Call):
        return _deco_name(node.func)
    return ""


def _name_of(node: py_ast.expr) -> str:
    if isinstance(node, py_ast.Name):
        return node.id
    if isinstance(node, py_ast.Attribute):
        return f"{_name_of(node.value)}.{node.attr}"
    return ""


# ── JavaScript / TypeScript parser (tree-sitter) ──────────────────────────────


def _parse_js_ts(source: str, lang: Lang, info: FileInfo) -> None:
    parser = get_parser(lang)
    if parser is None:
        for m in re.finditer(r"""import\s+.*?\s+from\s+['"]([^'"]+)['"]""", source):
            info.imports.append(
                ImportInfo(
                    source=m.group(1),
                    names=["*"],
                    is_relative=m.group(1).startswith("."),
                    line=source[: m.start()].count("\n") + 1,
                )
            )
        for m in re.finditer(r"""require\(['"]([^'"]+)['"]\)""", source):
            info.imports.append(
                ImportInfo(
                    source=m.group(1),
                    names=["*"],
                    is_relative=m.group(1).startswith("."),
                    line=source[: m.start()].count("\n") + 1,
                )
            )
        # Dynamic import('...') — React.lazy, code splitting, etc.
        for m in re.finditer(r"""import\(['"]([^'"]+)['"]\)""", source):
            info.imports.append(
                ImportInfo(
                    source=m.group(1),
                    names=["*"],
                    is_relative=m.group(1).startswith("."),
                    line=source[: m.start()].count("\n") + 1,
                )
            )
        return

    tree = parser.parse(source.encode("utf-8"))
    _walk_js_node(tree.root_node, source, info)


def _walk_js_node(node: Any, source: str, info: FileInfo) -> None:
    """Recursively walk a JS/TS tree-sitter node."""
    ntype = node.type

    # Import statements: import X from 'y'
    if ntype == "import_statement":
        src = _js_import_source(node, source)
        names = _js_import_names(node, source)
        line = node.start_point[0] + 1
        if src:
            info.imports.append(
                ImportInfo(
                    source=src,
                    names=names,
                    is_relative=src.startswith("."),
                    line=line,
                )
            )

    # require() calls: const x = require('y')
    elif ntype in ("call_expression", "new_expression"):
        _extract_require(node, source, info)

    # Function declarations
    elif ntype in ("function_declaration", "generator_function_declaration"):
        name = _js_child_text(node, "identifier", source)
        if name:
            info.functions.append(
                FunctionInfo(
                    name=name,
                    line=node.start_point[0] + 1,
                    is_async=_has_child_type(node, "async"),
                )
            )

    # Arrow functions assigned to variables
    elif ntype == "lexical_declaration":
        _extract_arrow_fn(node, source, info)

    # Class declarations
    elif ntype == "class_declaration":
        name = _js_child_text(node, "identifier", source)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))

    # Export declarations
    elif ntype in ("export_statement", "export_default_declaration"):
        _extract_export(node, source, info)

    for child in node.children:
        _walk_js_node(child, source, info)


def _js_import_source(node: Any, source: str) -> str:
    for child in node.children:
        if child.type in ("string", "template_string"):
            return source[child.start_byte : child.end_byte].strip("'\"` ")
    return ""


def _js_import_names(node: Any, source: str) -> list[str]:
    names: list[str] = []
    for child in node.children:
        if child.type == "import_clause":
            for sub in child.children:
                if sub.type == "identifier":
                    names.append(source[sub.start_byte : sub.end_byte])
                elif sub.type == "named_imports":
                    for item in sub.children:
                        if item.type == "import_specifier":
                            for n in item.children:
                                if n.type == "identifier":
                                    names.append(source[n.start_byte : n.end_byte])
                                    break
    return names or ["*"]


def _extract_require(node: Any, source: str, info: FileInfo) -> None:
    """Extract require('...') and dynamic import('...') calls."""
    func = None
    args = []
    for child in node.children:
        if child.type == "identifier":
            func = source[child.start_byte : child.end_byte]
        elif child.type == "import":
            # Dynamic import() — tree-sitter parses 'import' as its own node type
            func = "import"
        elif child.type == "arguments":
            for a in child.children:
                if a.type in ("string", "template_string"):
                    args.append(source[a.start_byte : a.end_byte].strip("'\"` "))
    if func in ("require", "import") and args:
        info.imports.append(
            ImportInfo(
                source=args[0],
                names=["*"],
                is_relative=args[0].startswith("."),
                line=node.start_point[0] + 1,
            )
        )


def _extract_arrow_fn(node: Any, source: str, info: FileInfo) -> None:
    """Extract const foo = () => {} or const foo = async () => {}."""
    for decl in node.children:
        if decl.type == "variable_declarator":
            name = None
            for child in decl.children:
                if child.type == "identifier" and name is None:
                    name = source[child.start_byte : child.end_byte]
                elif child.type in ("arrow_function", "function") and name:
                    is_async = _has_child_type(child, "async")
                    info.functions.append(
                        FunctionInfo(
                            name=name,
                            line=node.start_point[0] + 1,
                            is_async=is_async,
                        )
                    )
                    break


def _extract_export(node: Any, source: str, info: FileInfo) -> None:
    for child in node.children:
        if child.type == "identifier":
            name = source[child.start_byte : child.end_byte]
            if name not in info.exports:
                info.exports.append(name)


def _js_child_text(node: Any, child_type: str, source: str) -> str:
    for child in node.children:
        if child.type == child_type:
            return source[child.start_byte : child.end_byte]
    return ""


def _has_child_type(node: Any, child_type: str) -> bool:
    return any(c.type == child_type for c in node.children)


# ── Rust parser (tree-sitter) ─────────────────────────────────────────────────


def _parse_rust(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.RUST)
    if parser is None:
        _parse_generic(source, info)
        return

    tree = parser.parse(source.encode("utf-8"))
    _walk_rust_node(tree.root_node, source, info)


def _walk_rust_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type

    if ntype == "use_declaration":
        path = _node_text(node, source)
        names = ["*"]
        is_rel = path.starts_with("crate") or path.starts_with("self") or path.starts_with("super")
        if path:
            info.imports.append(
                ImportInfo(
                    source=path, names=names, is_relative=is_rel, line=node.start_point[0] + 1
                )
            )

    elif ntype == "extern_crate_declaration":
        name = _node_text(node, source)
        if name:
            info.imports.append(
                ImportInfo(
                    source=name.strip(";"),
                    names=["*"],
                    is_relative=False,
                    line=node.start_point[0] + 1,
                )
            )

    elif ntype == "mod_item":
        name = _node_text(node, source)
        if name and ";" in name:
            name = name.split(";")[0].strip()
            parts = name.split()
            if len(parts) >= 2 and parts[0] == "mod":
                name = parts[1]
        if name and name != "mod" and "{" not in name:
            info.imports.append(
                ImportInfo(source=name, names=["*"], is_relative=True, line=node.start_point[0] + 1)
            )

    elif ntype in ("function_item", "function_signature_item"):
        name = _rust_child_text(node, "identifier", source)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))

    elif ntype in ("struct_item", "enum_item", "trait_item", "type_item"):
        name = _rust_child_text(node, "identifier", source)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))

    elif ntype == "impl_item":
        trait = _rust_child_text(node, "trait_type", source) or ""
        for child in node.children:
            if child.type in ("function_item", "function_signature_item"):
                fn_name = _rust_child_text(child, "identifier", source)
                if fn_name:
                    display = f"{trait}::{fn_name}" if trait else fn_name
                    info.functions.append(FunctionInfo(name=display, line=child.start_point[0] + 1))

    elif ntype == "call_expression":
        func = ""
        for child in node.children:
            if child.type in ("field_expression", "identifier", "scoped_identifier"):
                func = _node_text(child, source)
                break
        if func and "." in func:
            parts = func.split(".")
            method = parts[-1]
            if method in ("get", "post", "put", "delete", "patch", "route", "nest_service"):
                for child in node.children:
                    if child.type == "arguments":
                        for arg in child.children:
                            atype = arg.type
                            if atype in ("string_literal", "raw_string_literal"):
                                route = _node_text(arg, source).strip("\"'")
                                if route and route.startswith("/"):
                                    info.exports.append(f"route:{route}")

    for child in node.children:
        _walk_rust_node(child, source, info)


def _rust_child_text(node: Any, field_name: str, source: str) -> str:
    for child in node.children:
        if child.type == field_name:
            return source[child.start_byte : child.end_byte]
    return ""


# ── Svelte parser (tree-sitter) ──────────────────────────────────────────────


def _parse_svelte(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.SVELTE)
    if parser is None:
        _parse_html(source, info)
        return

    tree = parser.parse(source.encode("utf-8"))
    _walk_svelte_node(tree.root_node, source, info)


def _walk_svelte_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type

    if ntype == "script_element":
        for child in node.children:
            if child.type == "raw_text":
                script_src = source[child.start_byte : child.end_byte]
                _parse_js_ts(script_src, Lang.JAVASCRIPT, info)

    elif ntype == "element":
        tag = ""
        for c in node.children:
            if c.type == "tag_name":
                tag = source[c.start_byte : c.end_byte]
                break
        if tag in ("a", "button", "input", "form", "select", "textarea", "nav"):
            info.exports.append(f"<{tag}>")

    elif ntype == "html_element":
        pass  # handled by children

    for child in node.children:
        _walk_svelte_node(child, source, info)


def _node_text(node: Any, source: str) -> str:
    buf = source.encode("utf-8")
    return buf[node.start_byte : node.end_byte].decode("utf-8", errors="replace").strip()


# ── Tree-sitter helpers (shared by all language parsers) ───────────────────


def _ts_node_text(node: Any, buf: bytes) -> str:
    try:
        if hasattr(node, "start_byte") and hasattr(node, "end_byte"):
            return buf[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
    except Exception as e:
        _log.debug("_ts_node_text failed: %s", e)
    return ""


def _ts_child_by_field(node: Any, field: str) -> Any | None:
    try:
        return node.child_by_field_name(field) if hasattr(node, "child_by_field_name") else None
    except Exception as e:
        _log.debug("_ts_child_by_field failed: %s", e)
        return None


def _ts_children(node: Any) -> list[Any]:
    try:
        return list(node.children) if hasattr(node, "children") else []
    except Exception as e:
        _log.debug("_ts_children failed: %s", e)
        return []


def _ts_node_type(node: Any) -> str:
    try:
        return node.type if hasattr(node, "type") else ""
    except Exception as e:
        _log.debug("_ts_node_type failed: %s", e)
        return ""


def _ts_extract_annotations(node: Any, buf: bytes) -> list[str]:
    """Extract Java annotation/decorator text from a node."""
    annotations: list[str] = []
    for child in _ts_children(node):
        ctype = _ts_node_type(child)
        if ctype in ("marker_annotation", "annotation"):
            text = _ts_node_text(child, buf)
            if text:
                annotations.append(text.strip())
    return annotations


def _ts_spring_route(annotation: str) -> str:
    """Extract route path from a Spring annotation like @GetMapping(\"/api/foo\")."""
    import re

    m = re.search(
        r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*[\"']([^\"']+)[\"']", annotation
    )
    return m.group(1) if m else ""


# ── Java parser (tree-sitter) ─────────────────────────────────────────────


def _parse_java(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.JAVA)
    if parser is None:
        _parse_java_regex(source, info)
        return
    tree = parser.parse(source.encode("utf-8"))
    _walk_java(tree.root_node, source.encode("utf-8"), info)


def _parse_java_regex(source: str, info: FileInfo) -> None:
    """Fallback regex when tree-sitter is unavailable."""
    for m in re.finditer(r"^import\s+(?:static\s+)?([\w.]+(?:\*)?)\s*;", source, re.MULTILINE):
        info.imports.append(ImportInfo(source=m.group(1), names=["*"], is_relative=False))
    for m in re.finditer(r"class\s+(\w+)", source):
        info.classes.append(ClassInfo(name=m.group(1), line=source[: m.start()].count(chr(10)) + 1))
    for m in re.finditer(
        r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*[\"']([^\"']+)[\"']",
        source,
    ):
        info.exports.append(f"route:{m.group(2)}")


def _walk_java(node: Any, buf: bytes, info: FileInfo) -> None:
    ntype = _ts_node_type(node)
    if ntype == "import_declaration":
        path_node = _ts_child_by_field(node, "name")
        if not path_node:
            path_node = _ts_child_by_field(node, "path")
        if not path_node:
            for c in _ts_children(node):
                if _ts_node_type(c) in ("scoped_identifier", "identifier"):
                    path_node = c
                    break
        path = _ts_node_text(path_node, buf) if path_node else ""
        if path:
            info.imports.append(ImportInfo(source=path, names=["*"], is_relative=False))
    elif ntype in (
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
    ):
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "method_declaration":
        name_node = _ts_child_by_field(node, "name")
        name = _ts_node_text(name_node, buf) if name_node else ""
        if name:
            annotations = _ts_extract_annotations(node, buf)
            info.functions.append(
                FunctionInfo(name=name, line=node.start_point[0] + 1, decorators=annotations)
            )
            for a in annotations:
                route = _ts_spring_route(a)
                if route and f"route:{route}" not in info.exports:
                    info.exports.append(f"route:{route}")
    for child in _ts_children(node):
        _walk_java(child, buf, info)


# ── Go parser (tree-sitter) ────────────────────────────────────────────────


def _parse_go(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.GO)
    if parser is None:
        _parse_go_regex(source, info)
        return
    tree = parser.parse(source.encode("utf-8"))
    _walk_go(tree.root_node, source.encode("utf-8"), info)


def _parse_go_regex(source: str, info: FileInfo) -> None:
    for m in re.finditer(r'^import\s+"([^"]+)"', source, re.MULTILINE):
        info.imports.append(ImportInfo(source=m.group(1), names=["*"], is_relative=False))
    for m in re.finditer(r'^\s+"([^"]+)"', source, re.MULTILINE):
        info.imports.append(ImportInfo(source=m.group(1), names=["*"], is_relative=False))
    for m in re.finditer(r"^func\s+(?:\([^)]*\)\s*)?(\w+)", source, re.MULTILINE):
        info.functions.append(
            FunctionInfo(name=m.group(1), line=source[: m.start()].count(chr(10)) + 1)
        )
    for m in re.finditer(r"r\.(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*[\"']([^\"']+)[\"']", source):
        info.exports.append(f"route:{m.group(2)}")


def _walk_go(node: Any, buf: bytes, info: FileInfo) -> None:
    ntype = _ts_node_type(node)
    if ntype == "import_declaration":
        for c in _ts_children(node):
            if _ts_node_type(c) == "import_spec":
                path_node = _ts_child_by_field(c, "path")
                if path_node:
                    path = _ts_node_text(path_node, buf).strip('"`')
                    if path:
                        info.imports.append(ImportInfo(source=path, names=["*"], is_relative=False))
    elif ntype == "function_declaration":
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "method_declaration":
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "type_declaration":
        for child in _ts_children(node):
            _walk_go(child, buf, info)
    elif ntype == "type_spec":
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "call_expression":
        func = _ts_child_by_field(node, "function")
        args = _ts_child_by_field(node, "arguments")
        if func:
            func_text = _ts_node_text(func, buf)
            if func_text and "." in func_text and args:
                route = _ts_go_route(func_text, args, buf)
                if route:
                    info.exports.append(f"route:{route}")
    for child in _ts_children(node):
        _walk_go(child, buf, info)


def _ts_go_route(func_text: str, args_node: Any, buf: bytes) -> str:
    """Extract route path from Go router calls like r.GET(\"/api/foo\")."""
    methods = {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "Any",
        "Handle",
        "HandleFunc",
    }
    parts = func_text.split(".")
    if len(parts) < 2:
        return ""
    method = parts[-1]
    if method not in methods:
        return ""
    for child in _ts_children(args_node):
        if _ts_node_type(child) in (
            "interpreted_string_literal",
            "string_literal",
            "raw_string_literal",
        ):
            path = _ts_node_text(child, buf).strip('"`')
            if path:
                return path
    return ""


# ── C/C++ parser (tree-sitter) ────────────────────────────────────────────


def _parse_c_cpp(source: str, info: FileInfo) -> None:
    lang = info.language
    parser = get_parser(lang)
    if parser is None:
        _parse_c_cpp_regex(source, info)
        return
    tree = parser.parse(source.encode("utf-8"))
    _walk_c_cpp(tree.root_node, source.encode("utf-8"), info, lang)


def _parse_c_cpp_regex(source: str, info: FileInfo) -> None:
    for m in re.finditer(r"^#\s*include\s+[<\"]([^>\"]+)[>\"]", source, re.MULTILINE):
        info.imports.append(ImportInfo(source=m.group(1), names=["*"], is_relative=False))
    for m in re.finditer(
        r"^(?:static\s+)?\w+(?:\s*\*+)?\s+(\w+)\s*\([^)]*\)\s*\{", source, re.MULTILINE
    ):
        info.functions.append(
            FunctionInfo(name=m.group(1), line=source[: m.start()].count(chr(10)) + 1)
        )


def _walk_c_cpp(node: Any, buf: bytes, info: FileInfo, lang: Lang) -> None:
    ntype = _ts_node_type(node)
    if ntype == "preproc_include":
        path_node = _ts_child_by_field(node, "path")
        if not path_node:
            for c in _ts_children(node):
                if _ts_node_type(c) in ("string_literal", "system_lib_string"):
                    path_node = c
                    break
        path = _ts_node_text(path_node, buf).strip('"<>') if path_node else ""
        if path:
            info.imports.append(ImportInfo(source=path, names=["*"], is_relative=False))
    elif ntype == "function_definition":
        decl = _ts_child_by_field(node, "declarator")
        name = ""
        if decl:
            name_node = _ts_child_by_field(decl, "declarator")
            if not name_node:
                name_node = _ts_child_by_field(decl, "name")
            if name_node:
                name = _ts_node_text(name_node, buf) or ""
        if not name:
            full = _ts_node_text(node, buf)
            idx = full.find("(")
            if idx > 0:
                name = full[:idx].rsplit(None, 1)[-1]
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "class_specifier":
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "struct_specifier":
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    for child in _ts_children(node):
        _walk_c_cpp(child, buf, info, lang)


# ── Swift parser (tree-sitter) ──────────────────────────────────────────────


def _parse_swift(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.SWIFT)
    if parser is None:
        _parse_swift_regex(source, info)
        return
    tree = parser.parse(source.encode("utf-8"))
    _walk_swift(tree.root_node, source.encode("utf-8"), info)


def _parse_swift_regex(source: str, info: FileInfo) -> None:
    for m in re.finditer(r"^import\s+(\w+)", source, re.MULTILINE):
        lineno = source[: m.start()].count(chr(10)) + 1
        info.imports.append(
            ImportInfo(source=m.group(1), names=["*"], is_relative=False, line=lineno)
        )
    for m in re.finditer(r"(?:public\s+)?(?:class|struct|enum|protocol|extension)\s+(\w+)", source):
        info.classes.append(ClassInfo(name=m.group(1), line=source[: m.start()].count(chr(10)) + 1))
    for m in re.finditer(r"(?:public\s+)?func\s+(\w+)\s*\(", source):
        info.functions.append(
            FunctionInfo(name=m.group(1), line=source[: m.start()].count(chr(10)) + 1)
        )


def _walk_swift(node: Any, buf: bytes, info: FileInfo) -> None:
    ntype = _ts_node_type(node)
    if ntype == "import_declaration":
        path_node = _ts_child_by_field(node, "path")
        if not path_node:
            for c in _ts_children(node):
                if _ts_node_type(c) in ("identifier", "member_access"):
                    path_node = c
                    break
        path = _ts_node_text(path_node, buf) if path_node else ""
        if path:
            info.imports.append(
                ImportInfo(
                    source=path, names=["*"], is_relative=False, line=node.start_point[0] + 1
                )
            )
    elif ntype in (
        "class_declaration",
        "struct_declaration",
        "enum_declaration",
        "protocol_declaration",
        "extension_declaration",
    ):
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "function_declaration":
        name = _ts_node_text(_ts_child_by_field(node, "name"), buf)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    for child in _ts_children(node):
        _walk_swift(child, buf, info)


# ── Ruby parser (tree-sitter) ───────────────────────────────────────────────


def _parse_ruby(source: str, info: FileInfo) -> None:
    parser = get_parser(Lang.RUBY)
    if parser is None:
        _parse_ruby_regex(source, info)
        return
    tree = parser.parse(source.encode("utf-8"))
    _walk_ruby(tree.root_node, source.encode("utf-8"), info)


def _parse_ruby_regex(source: str, info: FileInfo) -> None:
    for m in re.finditer(
        r'^\s*(?:require|require_relative|load)\s+["\']([^"\']+)["\']', source, re.MULTILINE
    ):
        info.imports.append(
            ImportInfo(
                source=m.group(1),
                names=["*"],
                is_relative=m.group(0).strip().startswith("require_relative"),
                line=source[: m.start()].count(chr(10)) + 1,
            )
        )
    for m in re.finditer(r"^\s*(?:class|module)\s+(\w+(?:::\w+)*)", source, re.MULTILINE):
        info.classes.append(ClassInfo(name=m.group(1), line=source[: m.start()].count(chr(10)) + 1))
    for m in re.finditer(r"^\s*def\s+(?:self\.)?(\w+)", source, re.MULTILINE):
        info.functions.append(
            FunctionInfo(name=m.group(1), line=source[: m.start()].count(chr(10)) + 1)
        )
    for m in re.finditer(
        r"(?:get|post|put|patch|delete|resources)\s+['\"]([^'\"]+)['\"]", source, re.MULTILINE
    ):
        info.exports.append(f"route:{m.group(1)}")


def _walk_ruby(node: Any, buf: bytes, info: FileInfo) -> None:
    ntype = _ts_node_type(node)
    if ntype == "call":
        method = ""
        args: list[str] = []
        for c in _ts_children(node):
            ctype = _ts_node_type(c)
            if ctype == "identifier":
                method = _ts_node_text(c, buf)
            elif ctype == "argument_list":
                for a in _ts_children(c):
                    if _ts_node_type(a) == "string":
                        args.append(_ts_node_text(a, buf).strip("\"'"))
        if method in ("require", "require_relative", "load"):
            for arg in args:
                info.imports.append(
                    ImportInfo(
                        source=arg,
                        names=["*"],
                        is_relative=(method == "require_relative"),
                        line=node.start_point[0] + 1,
                    )
                )
        elif method in ("get", "post", "put", "patch", "delete", "resources"):
            for arg in args:
                info.exports.append(f"route:{arg}")
    elif ntype == "method":
        for c in _ts_children(node):
            if _ts_node_type(c) == "identifier":
                name = _ts_node_text(c, buf)
                if name:
                    info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
                break
    elif ntype in ("class", "module"):
        for c in _ts_children(node):
            if _ts_node_type(c) == "constant":
                name = _ts_node_text(c, buf)
                if name:
                    info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
                break
    for child in _ts_children(node):
        _walk_ruby(child, buf, info)


# ── JSON parser ────────────────────────────────────────────────────────────────


# ── JSON parser ────────────────────────────────────────────────────────────────


def _parse_json(source: str, info: FileInfo) -> None:
    import json

    try:
        data = json.loads(source)
    except json.JSONDecodeError:
        info.error = "Invalid JSON"
        return

    if isinstance(data, dict):
        # package.json style
        if "dependencies" in data or "devDependencies" in data:
            for dep in {**data.get("dependencies", {}), **data.get("devDependencies", {})}.keys():
                info.imports.append(ImportInfo(source=dep, names=["*"], is_relative=False, line=0))
        if "main" in data:
            info.exports.append(data["main"])
        if "scripts" in data:
            info.functions.extend([FunctionInfo(name=k, line=0) for k in data["scripts"].keys()])


# ── YAML parser (yaml.safe_load) ─────────────────────────────────────────────


def _parse_yaml(source: str, info: FileInfo) -> None:
    try:
        import yaml
    except ImportError:
        info.error = "pyyaml not installed"
        return
    try:
        data = yaml.safe_load(source)
    except Exception as exc:
        info.error = f"yaml parse: {exc}"
        return
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        if key == "uses" and isinstance(value, str):
            info.imports.append(ImportInfo(source=value, names=["*"], is_relative=False, line=0))
        elif key == "image" and isinstance(value, str):
            info.imports.append(
                ImportInfo(source=value, names=["docker"], is_relative=False, line=0)
            )
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    sub_uses = item.get("uses")
                    if sub_uses:
                        info.imports.append(
                            ImportInfo(source=sub_uses, names=["*"], is_relative=False, line=0)
                        )
                    sub_image = item.get("image")
                    if sub_image:
                        info.imports.append(
                            ImportInfo(
                                source=sub_image, names=["docker"], is_relative=False, line=0
                            )
                        )


# ── PHP parser ────────────────────────────────────────────────────────────────


def _parse_php(source: str, info: FileInfo) -> None:
    """Parse PHP using tree-sitter (AST)."""
    parser = get_parser(Lang.PHP)
    if parser is None:
        _parse_php_regex(source, info)
        return

    try:
        tree = parser.parse(source.encode("utf-8"))
        _walk_php_node(tree.root_node, source, info)
    except Exception as e:
        _log.warning("_parse_php failed: %s", e)
        _parse_php_regex(source, info)


def _parse_php_regex(source: str, info: FileInfo) -> None:
    """Regex fallback for PHP when tree-sitter unavailable."""
    for m in re.finditer(r"""(?:require|include)(?:_once)?\s*\(?['"](.*?)['"]\)?""", source):
        path = m.group(1)
        info.imports.append(
            ImportInfo(
                source=path,
                names=["*"],
                is_relative=path.startswith("."),
                line=source[: m.start()].count("\n") + 1,
            )
        )
    for m in re.finditer(r"""use\s+([\w\\]+)(?:\s+as\s+\w+)?;""", source):
        info.imports.append(
            ImportInfo(
                source=m.group(1),
                names=["*"],
                is_relative=False,
                line=source[: m.start()].count("\n") + 1,
            )
        )
    for m in re.finditer(r"""function\s+(\w+)\s*\(""", source):
        info.functions.append(
            FunctionInfo(name=m.group(1), line=source[: m.start()].count("\n") + 1)
        )
    for m in re.finditer(r"""class\s+(\w+)""", source):
        info.classes.append(ClassInfo(name=m.group(1), line=source[: m.start()].count("\n") + 1))


def _walk_php_node(node: Any, source: str, info: FileInfo) -> None:
    """Walk PHP tree-sitter AST to extract imports, functions, classes."""
    ntype = node.type

    if ntype == "namespace_use_declaration":
        path = _node_text(node, source).removeprefix("use ")
        if path:
            info.imports.append(
                ImportInfo(
                    source=path.rstrip(";"),
                    names=["*"],
                    is_relative=False,
                    line=node.start_point[0] + 1,
                )
            )

    elif ntype in (
        "require_expression",
        "require_once_expression",
        "include_expression",
        "include_once_expression",
    ):
        path = _php_extract_include_path(node, source)
        if path:
            info.imports.append(
                ImportInfo(
                    source=path,
                    names=["*"],
                    is_relative=not path.startswith("/"),
                    line=node.start_point[0] + 1,
                )
            )

    elif ntype == "function_definition":
        name = _php_child_text(node, "name", source)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))

    elif ntype == "method_declaration":
        name = _php_child_text(node, "name", source)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))

    elif ntype == "class_declaration":
        name = _php_child_text(node, "name", source)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))

    for child in node.children:
        _walk_php_node(child, source, info)


def _php_child_text(node: Any, field: str, source: str) -> str:
    """Extract text of a named child by field name."""
    for child in node.children:
        if child.type == field:
            return source[child.start_byte : child.end_byte]
    return ""


def _php_extract_include_path(node: Any, source: str) -> str | None:
    """Extract the file path from a PHP require/include expression."""
    for child in node.children:
        if child.type in ("encapsed_string", "string"):
            return _node_text(child, source).strip("\"'")
        if child.type == "binary_expression":
            parts = child.children
            for _i, p in enumerate(parts):
                if p.type in ("encapsed_string", "string"):
                    return _node_text(p, source).strip("\"'")
    return None


# ── HTML parser (tree-sitter) ───────────────────────────────────────────────


def _parse_html(source: str, info: FileInfo) -> None:
    """Parse HTML using tree-sitter, extracting script/src and stylesheet refs."""
    parser = get_parser(Lang.HTML)
    if parser is None:
        return
    try:
        tree = parser.parse(source.encode("utf-8"))
    except Exception as e:
        _log.warning("_parse_html failed: %s", e)
        return

    _walk_html(tree.root_node, source, info)


def _walk_html(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type
    if ntype == "script_element":
        src = _html_attr_value(node, "src", source)
        if src:
            info.imports.append(
                ImportInfo(
                    source=src,
                    names=["script"],
                    is_relative=not src.startswith("http"),
                    line=node.start_point[0] + 1,
                )
            )
    elif ntype == "element":
        tag = _html_tag_name(node, source)
        if tag == "link":
            rel = _html_attr_value(node, "rel", source)
            href = _html_attr_value(node, "href", source)
            if href and rel and "stylesheet" in rel.lower().split():
                info.imports.append(
                    ImportInfo(
                        source=href,
                        names=["style"],
                        is_relative=not href.startswith("http"),
                        line=node.start_point[0] + 1,
                    )
                )
    for child in node.children:
        _walk_html(child, source, info)


def _html_tag_name(node: Any, source: str) -> str:
    for child in node.children:
        if child.type == "tag_name":
            return source[child.start_byte : child.end_byte]
        if child.type == "start_tag":
            for sub in child.children:
                if sub.type == "tag_name":
                    return source[sub.start_byte : sub.end_byte]
    return ""


def _html_attr_value(node: Any, attr_name: str, source: str) -> str:
    start_tag = next((c for c in node.children if c.type == "start_tag"), None)
    if start_tag is None:
        return ""
    for child in start_tag.children:
        if child.type == "attribute":
            raw = source[child.start_byte : child.end_byte]
            parts = raw.split("=", 1)
            if len(parts) == 2 and parts[0].strip() == attr_name:
                val = parts[1].strip().strip("\"'")
                return val
    return ""


# ── C# parser (tree-sitter) ────────────────────────────────────────────────────


def _parse_csharp(source: str, info: FileInfo) -> None:
    """Parse C# using tree-sitter."""
    parser = get_parser(Lang.C_SHARP)
    if parser is None:
        return
    try:
        tree = parser.parse(source.encode("utf-8"))
        _walk_csharp_node(tree.root_node, source, info)
    except Exception as e:
        _log.warning("_parse_csharp failed: %s", e)


def _walk_csharp_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type
    if ntype == "using_directive":
        path = _node_text(node, source).removeprefix("using ").rstrip(";")
        if path:
            info.imports.append(
                ImportInfo(
                    source=path, names=["*"], is_relative=False, line=node.start_point[0] + 1
                )
            )
    elif ntype == "class_declaration":
        name = _csharp_child_text(node, "identifier", source)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "method_declaration":
        name = _csharp_child_text(node, "identifier", source) or _csharp_child_text(
            node, "name", source
        )
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    for child in node.children:
        _walk_csharp_node(child, source, info)


def _csharp_child_text(node: Any, field: str, source: str) -> str:
    for child in node.children:
        if child.type == field:
            return source[child.start_byte : child.end_byte]
    return ""


# ── Kotlin parser (tree-sitter) ────────────────────────────────────────────────


def _parse_kotlin(source: str, info: FileInfo) -> None:
    """Parse Kotlin using tree-sitter."""
    parser = get_parser(Lang.KOTLIN)
    if parser is None:
        return
    try:
        tree = parser.parse(source.encode("utf-8"))
        _walk_kotlin_node(tree.root_node, source, info)
    except Exception as e:
        _log.warning("_parse_kotlin failed: %s", e)


def _walk_kotlin_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type
    if ntype == "import":
        raw = _node_text(node, source)
        # Skip the `import` keyword child node (also type "import")
        if raw.strip() == "import" or raw.strip() == "*":
            return
        path = raw.removeprefix("import ").rstrip(";").removesuffix(".*")
        if path:
            info.imports.append(
                ImportInfo(
                    source=path, names=["*"], is_relative=False, line=node.start_point[0] + 1
                )
            )
    elif ntype == "class_declaration":
        name = _kotlin_child_text(node, "identifier", source)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "function_declaration":
        name = _kotlin_child_text(node, "identifier", source)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    for child in node.children:
        _walk_kotlin_node(child, source, info)


def _kotlin_child_text(node: Any, field: str, source: str) -> str:
    for child in node.children:
        if child.type == field:
            return source[child.start_byte : child.end_byte]
    return ""


# ── Dart parser (tree-sitter) ──────────────────────────────────────────────────


def _parse_dart(source: str, info: FileInfo) -> None:
    """Parse Dart using tree-sitter."""
    parser = get_parser(Lang.DART)
    if parser is None:
        return
    try:
        tree = parser.parse(source.encode("utf-8"))
        _walk_dart_node(tree.root_node, source, info)
    except Exception as e:
        _log.warning("_parse_dart failed: %s", e)


def _walk_dart_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type
    if ntype == "library_import":
        raw = _node_text(node, source).strip(";")
        if raw.startswith("import "):
            raw = raw[7:].strip()
        is_rel = raw.startswith(("'", '"', "."))
        path = raw.strip("'\"")
        if path:
            info.imports.append(
                ImportInfo(
                    source=path, names=["*"], is_relative=is_rel, line=node.start_point[0] + 1
                )
            )
    elif ntype == "class_definition":
        name = _dart_child_text(node, "identifier", source)
        if name:
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype in (
        "method_declaration",
        "function_declaration",
        "getter_declaration",
        "setter_declaration",
    ):
        name = _dart_child_text(node, "identifier", source)
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    for child in node.children:
        _walk_dart_node(child, source, info)


def _dart_child_text(node: Any, field: str, source: str) -> str:
    for child in node.children:
        if child.type == field:
            return source[child.start_byte : child.end_byte]
    return ""


# ── Bash parser (tree-sitter) ──────────────────────────────────────────────────


def _parse_bash(source: str, info: FileInfo) -> None:
    """Parse Bash using tree-sitter."""
    parser = get_parser(Lang.BASH)
    if parser is None:
        _parse_bash_regex(source, info)
        return
    try:
        tree = parser.parse(source.encode("utf-8"))
        _walk_bash_node(tree.root_node, source, info)
    except Exception as e:
        _log.warning("_parse_bash failed: %s", e)
        _parse_bash_regex(source, info)


def _parse_bash_regex(source: str, info: FileInfo) -> None:
    """Regex fallback for Bash."""
    for m in re.finditer(r"""^(?:source|\.)\s+['"]?([^\s'"]+)['"]?""", source, re.MULTILINE):
        info.imports.append(
            ImportInfo(
                source=m.group(1),
                names=["*"],
                is_relative=True,
                line=source[: m.start()].count("\n") + 1,
            )
        )


def _walk_bash_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type
    if ntype == "function_definition":
        name_node = _bash_child_by_type(node, "word")
        name = _node_text(name_node, source) if name_node else ""
        if name:
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    elif ntype == "command":
        cmd_name = ""
        for child in node.children:
            if child.type == "command_name":
                cmd_name = _node_text(child, source)
                break
        if cmd_name in ("source", "."):
            for child in node.children:
                path = ""
                if child.type == "word":
                    path = _node_text(child, source).strip("\"'")
                elif child.type == "string":
                    for sub in child.children:
                        if sub.type == "string_content":
                            path = _node_text(sub, source).strip("\"'")
                            break
                if path:
                    info.imports.append(
                        ImportInfo(
                            source=path, names=["*"], is_relative=True, line=node.start_point[0] + 1
                        )
                    )
    for child in node.children:
        _walk_bash_node(child, source, info)


def _bash_child_by_type(node: Any, ntype: str) -> Any:
    for child in node.children:
        if child.type == ntype:
            return child
    return None


# ── CSS parser (tree-sitter) ───────────────────────────────────────────────────


def _parse_css(source: str, info: FileInfo) -> None:
    """Parse CSS using tree-sitter."""
    parser = get_parser(Lang.CSS)
    if parser is None:
        return
    try:
        tree = parser.parse(source.encode("utf-8"))
        _walk_css_node(tree.root_node, source, info)
    except Exception as e:
        _log.warning("_parse_css failed: %s", e)


def _walk_css_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type
    if ntype == "import_statement":
        path = _node_text(node, source).replace("@import ", "").strip(" ;'\"")
        # Handle url() wrapper
        if path.startswith("url(") and path.endswith(")"):
            path = path[4:-1].strip("\"'")
        if path:
            info.imports.append(
                ImportInfo(
                    source=path,
                    names=["*"],
                    is_relative=not path.startswith(("http", "//")),
                    line=node.start_point[0] + 1,
                )
            )
    for child in node.children:
        _walk_css_node(child, source, info)


# ── SQL parser (tree-sitter) ───────────────────────────────────────────────────


def _parse_sql(source: str, info: FileInfo) -> None:
    """Parse SQL using tree-sitter."""
    parser = get_parser(Lang.SQL)
    if parser is None:
        return
    try:
        tree = parser.parse(source.encode("utf-8"))
        _walk_sql_node(tree.root_node, source, info)
    except Exception as e:
        _log.warning("_parse_sql failed: %s", e)


def _walk_sql_node(node: Any, source: str, info: FileInfo) -> None:
    ntype = node.type
    if ntype == "create_table":
        name_node = _sql_child_by_type(node, "identifier") or _sql_child_by_type(
            node, "object_reference"
        )
        if name_node:
            name = _node_text(name_node, source)
            info.classes.append(ClassInfo(name=name, line=node.start_point[0] + 1))
    elif ntype in ("create_view", "create_procedure", "create_function"):
        name_node = _sql_child_by_type(node, "identifier") or _sql_child_by_type(
            node, "object_reference"
        )
        if name_node:
            name = _node_text(name_node, source)
            info.functions.append(FunctionInfo(name=name, line=node.start_point[0] + 1))
    for child in node.children:
        _walk_sql_node(child, source, info)


def _sql_child_by_type(node: Any, ntype: str) -> Any:
    for child in node.children:
        if child.type == ntype:
            return child
    return None


# ── Scala parser (regex — no PyPI tree-sitter grammar available yet) ──────────


def _parse_scala_regex(source: str, info: FileInfo) -> None:
    """
    Regex-based Scala extraction. Intentional, not a placeholder: no
    tree-sitter-scala wheel is published on PyPI as of this writing, so this
    stays regex until a grammar ships (per the language expansion plan) --
    unlike the other regex fallbacks in this file, which back up a tree-sitter
    primary path that usually succeeds.
    """
    for m in re.finditer(r"^\s*import\s+([\w.]+(?:\.\{[^}]*\})?)", source, re.MULTILINE):
        info.imports.append(
            ImportInfo(
                source=m.group(1),
                names=["*"],
                is_relative=False,
                line=source[: m.start()].count("\n") + 1,
            )
        )
    for m in re.finditer(
        r"^\s*(?:private\s+|protected\s+|final\s+)*def\s+(\w+)", source, re.MULTILINE
    ):
        info.functions.append(
            FunctionInfo(name=m.group(1), line=source[: m.start()].count("\n") + 1)
        )
    for m in re.finditer(r"^\s*(?:case\s+)?(?:class|object|trait)\s+(\w+)", source, re.MULTILINE):
        info.classes.append(ClassInfo(name=m.group(1), line=source[: m.start()].count("\n") + 1))


# ── Generic fallback parser ────────────────────────────────────────────────────


def _parse_generic(source: str, info: FileInfo) -> None:
    """Minimal extraction for languages without dedicated parsers."""
    pass


# ── Entry point detection ──────────────────────────────────────────────────────

ENTRY_POINT_NAMES = {
    "main.py",
    "app.py",
    "server.py",
    "index.py",
    "run.py",
    "manage.py",
    "index.js",
    "main.js",
    "server.js",
    "app.js",
    "index.ts",
    "main.ts",
    "index.html",
    "index.php",
    "wsgi.py",
    "asgi.py",
    "__main__.py",
}

ENTRY_POINT_PATTERNS = [
    re.compile(r"if\s+__name__\s*==\s*['\"]__main__['\"]"),  # Python main guard
    re.compile(r"app\.listen\("),  # Express
    re.compile(r"createServer\("),  # Node HTTP
    re.compile(r"ReactDOM\.render|createRoot"),  # React entry
    re.compile(r"FastAPI\(\)|Flask\(__name__\)"),  # Python web frameworks
    re.compile(r"uvicorn\.run\(|app\.run\("),  # Python server start
]


def _is_entry_point(path: Path, info: FileInfo) -> bool:
    if path.name in ENTRY_POINT_NAMES:
        return True
    # Check for framework entry patterns in the source (already parsed)
    return False  # pattern check on raw source done at scan time — could add if needed


# ── Purpose inference ──────────────────────────────────────────────────────────


def _infer_purpose(path: Path, info: FileInfo) -> str:
    """
    Infer a one-sentence plain English purpose from file name, location, and structure.
    This is a heuristic — not AI. scanner agents will improve on this.
    """
    name = path.stem.lower()
    parent = path.parent.name.lower()
    lang = info.language

    # Config files
    if path.name in {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "Cargo.toml",
        "go.mod",
        "composer.json",
    }:
        return "Project manifest and dependency definitions."
    if path.name in {".env", ".env.example", ".env.local"}:
        return "Environment variable definitions."
    if path.suffix in {".yml", ".yaml"} and parent in {"github", ".github", "workflows"}:
        return "CI/CD workflow automation."
    if path.name in {"docker-compose.yml", "docker-compose.yaml", "Dockerfile"}:
        return "Container configuration."

    # Test files
    if "test" in name or name.startswith("test_") or name.endswith("_test"):
        return f"Test file for {name.replace('test_', '').replace('_test', '')} module."
    if parent in {"tests", "test", "__tests__", "spec", "specs"}:
        return "Test file."

    # Common patterns
    if "route" in name or "router" in name:
        return f"Route definitions and URL handlers for {parent}."
    if "model" in name:
        return f"Data model definitions for {parent}."
    if "controller" in name or "handler" in name:
        return f"Request handler logic for {parent}."
    if "middleware" in name:
        return f"Middleware processing for {parent}."
    if "auth" in name or "login" in name or "session" in name:
        return "Authentication and session management."
    if "config" in name or "settings" in name:
        return "Application configuration."
    if "util" in name or "helper" in name or "utils" in name:
        return f"Utility functions shared across {parent}."
    if "schema" in name or "types" in name:
        return f"Type definitions and schema validation for {parent}."
    if "migration" in name:
        return "Database migration script."
    if "seed" in name or "fixture" in name:
        return "Database seed or fixture data."
    if info.is_entry_point:
        return "Application entry point."
    if info.classes and not info.functions:
        return f"Class definitions: {', '.join(c.name for c in info.classes[:3])}."
    if info.functions and not info.classes:
        return f"Function library: {', '.join(f.name for f in info.functions[:3])}."
    return f"{lang.value.title()} source file."
