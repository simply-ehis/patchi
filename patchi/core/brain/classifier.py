"""
File classifier — assigns a purpose label to every file in the project.

Philosophy (per supplementary spec §2 offline/AI split):
  80% of files can be classified from their AST and path alone — no AI cost.
  Only genuinely ambiguous files get an AI call.

Offline classification uses:
  - File path / name patterns (test_, __init__, cli/, routes/, etc.)
  - Export type (what functions/classes the file defines)
  - Import patterns (what the file imports)
  - File size and structure

AI classification (fallback only):
  - Called only when offline pass returns label="unknown"
  - Returns a plain-English one-liner describing the file's purpose
  - Result cached in brain.json so the call only happens once per file
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

# ── Offline label lookup ───────────────────────────────────────────────────────

_PATH_RULES: list[tuple[str, str]] = [
    # Path segment → label
    (r"test[_/]|[_/]test\.py$|tests?/", "test"),
    (r"__init__\.py$", "package init"),
    (r"cli[/\\]|commands?[/\\]", "CLI command"),
    (r"routes?[/\\]|router|handlers?[/\\]", "route handler"),
    (r"middleware[/\\]|middleware\.py", "middleware"),
    (r"models?[/\\]|schemas?[/\\]", "data model / schema"),
    (r"migrations?[/\\]|alembic[/\\]", "database migration"),
    (r"config[/\\]|settings[/\\]|conf\.py", "configuration"),
    (r"constants?\.py$|enums?\.py$", "constants / enums"),
    (r"utils?[/\\]|helpers?[/\\]", "utility functions"),
    (r"static[/\\]|assets?[/\\]", "static asset"),
    (r"templates?[/\\]|views?[/\\]", "template / view"),
    (r"security[/\\]|auth[/\\]", "auth / security"),
    (r"core[/\\]agents?[/\\]|core[/\\]fix[/\\]|core[/\\]security[/\\]", "agent / scanner"),
    (r"core[/\\]|engine[/\\]", "core engine"),
    (r"web[/\\]|server\.py$|api\.py$", "web server / API"),
    (r"agents?[/\\]|scanners?[/\\]", "agent / scanner"),
    (r"brain[/\\]", "brain module"),
    (r"fix[/\\]|fixer[/\\]", "fix agent"),
    (r"notify[/\\]|notification", "notification"),
    (r"queue\.py$|queue[/\\]", "queue system"),
    (r"memory\.py$|memory[/\\]", "memory store"),
    (r"health\.py$", "health checker"),
    (r"setup\.py$|pyproject\.toml$", "package setup"),
    (r"Makefile$|Dockerfile", "build / deploy"),
    (r"\.env$|\.env\.", "environment config"),
    (r"README|CHANGELOG|LICENSE|AGENTS", "documentation"),
    (r"requirements.*\.txt$", "dependency list"),
]

_IMPORT_SIGNALS: dict[str, str] = {
    "fastapi": "FastAPI route handler",
    "flask": "Flask route handler",
    "django": "Django view/model",
    "sqlalchemy": "database model/query",
    "pytest": "test file",
    "unittest": "test file",
    "click": "CLI command",
    "typer": "CLI command",
    "pydantic": "data schema / model",
    "celery": "background task",
    "redis": "cache / queue integration",
    "httpx": "HTTP client",
    "aiohttp": "async HTTP",
    "playwright": "browser automation",
    "selenium": "browser automation",
    "torch": "ML / AI model",
    "tensorflow": "ML / AI model",
    "sklearn": "ML / AI model",
    "logging": "utility / logging",
    "argparse": "CLI entry point",
    "rich": "CLI output formatting",
}


import logging

_log = logging.getLogger("patchi.brain.classifier")


def classify_file(rel_path: str, abs_path: Path) -> str:
    """
    Return a short plain-English purpose label for a file.
    Uses path patterns and AST — no AI call.
    """
    path_str = rel_path.replace("\\", "/").lower()

    # 1. Path-based rules — fastest, covers the majority
    for pattern, label in _PATH_RULES:
        if re.search(pattern, path_str):
            return label

    # 2. Extension quick exits
    ext = abs_path.suffix.lower()
    if ext in {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}:
        return "configuration / data file"
    if ext in {".md", ".rst", ".txt"}:
        return "documentation"
    if ext in {".html", ".jinja", ".j2"}:
        return "HTML template"
    if ext in {".css", ".scss", ".less"}:
        return "stylesheet"
    if ext in {".js", ".mjs"} and "test" not in path_str:
        return "JavaScript module"
    if ext in {".ts", ".tsx"} and "test" not in path_str:
        return "TypeScript module"

    if ext != ".py":
        return "source file"

    # 3. AST — read imports and top-level definitions
    try:
        src = abs_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src)
    except (SyntaxError, OSError):
        return "Python module"

    imports: list[str] = []
    top_fns: list[str] = []
    top_cls: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.append(a.name.split(".")[0].lower())
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module.split(".")[0].lower())
        elif isinstance(node, ast.FunctionDef):
            if node.col_offset == 0:
                top_fns.append(node.name)
        elif isinstance(node, ast.ClassDef):
            if node.col_offset == 0:
                top_cls.append(node.name)

    # 4. Import signal match
    for imp in imports:
        if imp in _IMPORT_SIGNALS:
            return _IMPORT_SIGNALS[imp]

    # 5. Top-level structure heuristics
    fn_names = " ".join(top_fns).lower()
    cl_names = " ".join(top_cls).lower()
    all_names = fn_names + " " + cl_names

    if re.search(r"\btest_\w+|\b\w+_test\b", fn_names):
        return "test file"
    if re.search(r"\bget_|post_|put_|delete_|patch_|handle_", fn_names):
        return "request handler"
    if re.search(r"\bscanner\b|\bscanner\b|\bdetect\b|\bcheck\b|\baudit\b", cl_names.lower()):
        return "scanner / detector"
    if re.search(r"\bagent\b|\bworker\b|\bcoordinator\b", all_names):
        return "agent / worker"
    if re.search(r"\bmodel\b|\bschema\b|\bentity\b", all_names):
        return "data model"
    if re.search(r"\bconfig\b|\bsetting\b|\boption\b", all_names):
        return "configuration"
    if re.search(r"\bcommand\b|\bcli\b|\bmain\b", fn_names) and "__main__" in src:
        return "CLI entry point"
    if re.search(r"\bcreate_app\b|\bapp = \b", src):
        return "application factory"

    return "Python module"


def batch_classify(
    files: list,  # list[FileInfo]
    root: Path,
    ai_config: dict | None = None,
    max_ai_calls: int = 20,
) -> dict[str, str]:
    """
    Classify all files. Returns {rel_path: purpose_label}.
    AI is called only for truly unknown files, capped at max_ai_calls.
    """
    result: dict[str, str] = {}
    needs_ai: list[str] = []

    for fi in files:
        abs_path = root / fi.path
        label = classify_file(fi.path, abs_path)
        if label == "Python module" and ai_config:
            needs_ai.append(fi.path)
        else:
            result[fi.path] = label

    # AI pass — only for genuinely ambiguous Python files
    if ai_config and needs_ai:
        from patchi.core.fix.base import _call_ai

        for rel_path in needs_ai[:max_ai_calls]:
            abs_path = root / rel_path
            try:
                snippet = (root / rel_path).read_text(encoding="utf-8", errors="ignore")[:600]
                prompt = (
                    f"What does this Python file do? Answer in one sentence, plain English, "
                    f"no code. File: {rel_path}\n\n{snippet}"
                )
                label = _call_ai(prompt, ai_config, max_tokens=60).strip()
                result[rel_path] = label or "Python module"
            except Exception as e:
                _log.warning("batch_classify failed: %s", e)
                result[rel_path] = "Python module"
        # remaining uncalled files
        for rel_path in needs_ai[max_ai_calls:]:
            result[rel_path] = "Python module"

    return result
