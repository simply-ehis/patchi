"""
Language registry for Patchi's Brain scanner.

Manages tree-sitter parsers for all supported languages.
Parsers are expensive to create — build once, reuse always.

Every language with a tree-sitter grammar gets AST-level parsing.
Languages without tree-sitter grammars (JSON, YAML) use stdlib/heuristic
parsing. All other languages use tree-sitter AST."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Parser


# ── Language enum ──────────────────────────────────────────────────────────────


class Lang(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    HTML = "html"
    CSS = "css"
    JSON = "json"
    SQL = "sql"
    BASH = "bash"
    YAML = "yaml"
    PHP = "php"
    JAVA = "java"
    C_SHARP = "c_sharp"
    RUBY = "ruby"
    GO = "go"
    RUST = "rust"
    CPP = "cpp"
    C = "c"
    SCALA = "scala"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    DART = "dart"
    SVELTE = "svelte"
    UNKNOWN = "unknown"


# ── Extension → Language map ───────────────────────────────────────────────────

EXTENSION_MAP: dict[str, Lang] = {
    ".py": Lang.PYTHON,
    ".pyw": Lang.PYTHON,
    ".js": Lang.JAVASCRIPT,
    ".mjs": Lang.JAVASCRIPT,
    ".cjs": Lang.JAVASCRIPT,
    ".jsx": Lang.JAVASCRIPT,
    ".ts": Lang.TYPESCRIPT,
    ".tsx": Lang.TYPESCRIPT,
    ".mts": Lang.TYPESCRIPT,
    ".html": Lang.HTML,
    ".htm": Lang.HTML,
    ".jinja": Lang.HTML,
    ".jinja2": Lang.HTML,
    ".j2": Lang.HTML,
    ".css": Lang.CSS,
    ".scss": Lang.CSS,
    ".sass": Lang.CSS,
    ".json": Lang.JSON,
    ".jsonc": Lang.JSON,
    ".sql": Lang.SQL,
    ".sh": Lang.BASH,
    ".bash": Lang.BASH,
    ".zsh": Lang.BASH,
    ".yml": Lang.YAML,
    ".yaml": Lang.YAML,
    ".php": Lang.PHP,
    ".php3": Lang.PHP,
    ".php4": Lang.PHP,
    ".php5": Lang.PHP,
    ".phtml": Lang.PHP,
    ".java": Lang.JAVA,
    ".cs": Lang.C_SHARP,
    ".rb": Lang.RUBY,
    ".go": Lang.GO,
    ".rs": Lang.RUST,
    ".cpp": Lang.CPP,
    ".cxx": Lang.CPP,
    ".cc": Lang.CPP,
    ".c": Lang.C,
    ".h": Lang.C,
    ".hpp": Lang.CPP,
    ".scala": Lang.SCALA,
    ".kt": Lang.KOTLIN,
    ".kts": Lang.KOTLIN,
    ".swift": Lang.SWIFT,
    ".dart": Lang.DART,
    ".svelte": Lang.SVELTE,
}

# Languages where tree-sitter gives us real AST parsing
TREE_SITTER_LANGS = {
    Lang.PYTHON,
    Lang.JAVASCRIPT,
    Lang.TYPESCRIPT,
    Lang.RUST,
    Lang.SVELTE,
    Lang.JAVA,
    Lang.GO,
    Lang.C,
    Lang.CPP,
    Lang.SWIFT,
    Lang.RUBY,
    Lang.PHP,
    Lang.C_SHARP,
    Lang.KOTLIN,
    Lang.DART,
    Lang.BASH,
    Lang.CSS,
    Lang.SQL,
    Lang.HTML,
}

# Config-style files detected by filename (not extension)
FILENAME_LANG_MAP: dict[str, Lang] = {
    "Makefile": Lang.BASH,
    ".bashrc": Lang.BASH,
    ".zshrc": Lang.BASH,
    ".env": Lang.BASH,
    ".htaccess": Lang.PHP,
}


def detect_language(path: Path) -> Lang:
    """Detect language from file path (extension first, filename fallback)."""
    by_name = FILENAME_LANG_MAP.get(path.name)
    if by_name:
        return by_name
    return EXTENSION_MAP.get(path.suffix.lower(), Lang.UNKNOWN)


# ── Parser registry ────────────────────────────────────────────────────────────

_parsers: dict[Lang, Parser] = {}


def get_parser(lang: Lang) -> Parser | None:
    """
    Return a cached tree-sitter Parser for the given language.
    Returns None for languages handled by regex (not tree-sitter).
    """
    if lang not in TREE_SITTER_LANGS:
        return None

    if lang not in _parsers:
        _parsers[lang] = _build_parser(lang)

    return _parsers[lang]


def _build_parser(lang: Lang) -> Parser:
    from tree_sitter import Language, Parser

    if lang == Lang.PYTHON:
        import tree_sitter_python as tspy

        return Parser(Language(tspy.language()))

    if lang == Lang.JAVASCRIPT:
        import tree_sitter_javascript as tsjs

        return Parser(Language(tsjs.language()))

    if lang == Lang.TYPESCRIPT:
        import tree_sitter_typescript as tsts

        return Parser(Language(tsts.language_typescript()))

    if lang == Lang.RUST:
        import tree_sitter_rust as tsrs

        return Parser(Language(tsrs.language()))

    if lang == Lang.SVELTE:
        import tree_sitter_svelte as tssv

        return Parser(Language(tssv.language()))

    if lang == Lang.JAVA:
        import tree_sitter_java as tsjava

        return Parser(Language(tsjava.language()))

    if lang == Lang.GO:
        import tree_sitter_go as tsgo

        return Parser(Language(tsgo.language()))

    if lang == Lang.C:
        import tree_sitter_c as tsc

        return Parser(Language(tsc.language()))

    if lang == Lang.CPP:
        import tree_sitter_cpp as tscpp

        return Parser(Language(tscpp.language()))

    if lang == Lang.SWIFT:
        import tree_sitter_swift as tssw

        return Parser(Language(tssw.language()))

    if lang == Lang.RUBY:
        import tree_sitter_ruby as tsrb

        return Parser(Language(tsrb.language()))

    if lang == Lang.PHP:
        import tree_sitter_php as tsphp

        return Parser(Language(tsphp.language_php()))

    if lang == Lang.C_SHARP:
        import tree_sitter_c_sharp as tscs

        return Parser(Language(tscs.language()))

    if lang == Lang.KOTLIN:
        import tree_sitter_kotlin as tskt

        return Parser(Language(tskt.language()))

    if lang == Lang.DART:
        import tree_sitter_dart as tsdart

        return Parser(Language(tsdart.language()))

    if lang == Lang.BASH:
        import tree_sitter_bash as tsbash

        return Parser(Language(tsbash.language()))

    if lang == Lang.CSS:
        import tree_sitter_css as tscss

        return Parser(Language(tscss.language()))

    if lang == Lang.SQL:
        import tree_sitter_sql as tssql

        return Parser(Language(tssql.language()))

    if lang == Lang.HTML:
        import tree_sitter_html as tshtml

        return Parser(Language(tshtml.language()))

    raise ValueError(f"No tree-sitter grammar for {lang}")


# ── Parse-once tree cache ────────────────────────────────────────────────────
# tree-sitter Trees are expensive to build and are NOT pickleable (they hold
# C pointers), so this cache is strictly per-process. Its job: during one run,
# every agent that parses the same file content gets the SAME tree instead of
# re-parsing it — the "single-pass scan" for the tree-sitter agents. In the
# process-pool mode each worker warms its own cache; the cache only dedupes
# WITHIN a worker, which is the correct trade-off (cross-process Trees are
# impossible by design).
#
# The cache key is the content hash, not the path: agents may hold different
# relative path spellings (os vs posix) for the same file, but content is
# unambiguous. Reading a file and parsing it is O(bytes); hashing is the
# cheaper half, so a hash-first design wins whenever two agents parse the
# same file — which is the entire scanner group during a run.

_CACHE_LIMIT = 512  # max cached trees; bounded so long sweeps don't balloon

_source_tree_cache: dict[tuple[str, str], Tree] = {}  # (lang, sha256) -> Tree
_cache_hits = 0
_cache_misses = 0


def parse_source(lang: Lang, source: str | bytes) -> Tree | None:
    """Parse `source` with the cached tree-sitter parser for `lang`.

    Returns the SAME tree object for identical (lang, content) pairs within
    this process — agents in one run stop re-parsing shared files. Returns
    None for languages without a tree-sitter grammar (regex/stdio fallback
    languages) or when parsing fails.
    """
    if lang not in TREE_SITTER_LANGS:
        return None

    if isinstance(source, str):
        source = source.encode("utf-8")

    try:
        import hashlib

        key = (lang.value, hashlib.sha256(source).hexdigest())
    except Exception:
        return None

    global _cache_hits, _cache_misses
    cached = _source_tree_cache.get(key)
    if cached is not None:
        _cache_hits += 1
        return cached

    parser = get_parser(lang)
    if parser is None:
        return None

    try:
        tree = parser.parse(source)
    except Exception:
        return None

    _cache_misses += 1
    if len(_source_tree_cache) >= _CACHE_LIMIT:
        # Bound memory: drop the oldest 25% of cached trees (dict preserves
        # insertion order), keeping the hot tail for the rest of the run.
        for old_key in list(_source_tree_cache)[: _CACHE_LIMIT // 4]:
            _source_tree_cache.pop(old_key, None)
    _source_tree_cache[key] = tree
    return tree


def parse_stats() -> dict[str, int]:
    """Return cache hit/miss counters (observability for the single-pass gate)."""
    return {
        "hits": _cache_hits,
        "misses": _cache_misses,
        "cached_trees": len(_source_tree_cache),
    }


def clear_source_tree_cache() -> int:
    """Drop all cached trees; returns how many were evicted.

    Used between runs and at process-pool worker startup so a long-lived
    process never serves stale trees (same content hash always reparses to
    the same tree, but keeping memory tight matters on big repos).
    """
    global _cache_hits, _cache_misses
    n = len(_source_tree_cache)
    _source_tree_cache.clear()
    _cache_hits = 0
    _cache_misses = 0
    return n


# ── Ignore dirs (shared with scanner + freshness) ─────────────────────────────

DEFAULT_IGNORE_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".patchi",
    ".venv",
    "venv",
    "env",
    ".env",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "coverage",
    ".coverage",
    "htmlcov",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
}
