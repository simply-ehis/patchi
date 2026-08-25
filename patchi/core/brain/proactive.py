"""
Proactive Agent — Phase 4 of the Patchi super-agent.

Turns a change-set into *safe, mechanical* fixes and applies them behind a flag.
This is the "proactive" half of Pillar 3's event table: when a file is saved,
Patchi proposes (and, with ``--apply``, performs) fixes such as:

    - missing_import   → a name is used but never imported/defined; add the import
    - unused_import    → an imported name is never referenced; drop the line
    - dead_code        → a top-level def is referenced nowhere; flag for removal
    - signature_callers→ a function's signature changed; list/update its callers
    - charter_violation→ the change breaks a guard-rail boundary
    - format           → run the project formatter (ruff/black) if available

Detection is offline (AST for Python, textual heuristics otherwise) and reads
only the Layered Brain / import graph — no raw re-scan of the whole repo.
Applying is always opt-in (``--apply`` for safe fixes, ``--unsafe`` for all).
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patchi.core.brain.import_graph import ImportGraph
    from patchi.core.brain.scanner import FileInfo

from patchi.core.brain import learning
from patchi.core.brain.layered_brain import _classify_subsystem, _module_of

# fix_type → (human label, is_safe_to_auto_apply)
_FIX_META: dict[str, tuple[str, bool]] = {
    "missing_import": ("Add missing import", True),
    "unused_import": ("Remove unused import", True),
    "dead_code": ("Remove dead code", True),
    "format": ("Format file", True),
    "signature_callers": ("Update callers after signature change", False),
    "charter_violation": ("Charter violation in change", False),
}


import logging

_log = logging.getLogger("patchi.brain.proactive")


@dataclass
class ProposedFix:
    """A single safe/proposed fix for one changed file."""

    fix_type: str
    file: str
    description: str
    safe: bool
    name: str = ""  # symbol involved (function/class/import name)
    suggested: str = ""  # e.g. the import line to add, or replacement text
    callers: list[str] = field(default_factory=list)
    line: int = 0  # line of the symbol (for UI/debug)

    def to_dict(self) -> dict:
        return {
            "fix_type": self.fix_type,
            "file": self.file,
            "description": self.description,
            "safe": self.safe,
            "name": self.name,
            "suggested": self.suggested,
            "callers": self.callers,
            "line": self.line,
        }


def _word_in_source(name: str, src: str) -> bool:
    return bool(re.search(rf"(?<![\w.]){re.escape(name)}(?![\w])", src))


class ProactiveAgent:
    """Proposes (and optionally applies) safe fixes for a change-set."""

    def __init__(self, root: Path):
        self.root = Path(root)

    # ── Analysis ────────────────────────────────────────────────────────────────

    def analyze_change(
        self,
        changed_files: list[str],
        file_infos: list[FileInfo],
        graph: ImportGraph | None = None,
        charter: object | None = None,
        include_format: bool = True,
    ) -> list[ProposedFix]:
        fi_map = {fi.path: fi for fi in file_infos}
        public_api: dict[str, str] = {}
        for fi in file_infos:
            for fn in fi.functions:
                public_api.setdefault(fn.name, fi.path)
            for cl in fi.classes:
                public_api.setdefault(cl.name, fi.path)

        # Shared read cache for this whole call. Without it, dead-code checking
        # re-reads every other file from disk for *every candidate symbol in
        # every file* — O(files^2 * symbols_per_file) disk reads. On a
        # whole-project scan (hundreds of files) that's well over a million
        # redundant reads and can make the call take minutes or effectively hang.
        # File contents don't change during this synchronous scan, so caching
        # is safe.
        src_cache: dict[str, str] = {}

        def _cached_read(path: str) -> str | None:
            if path not in src_cache:
                src = self._read(path)
                if src is None:
                    return None
                src_cache[path] = src
            return src_cache[path]

        fixes: list[ProposedFix] = []
        for path in changed_files:
            fi = fi_map.get(path)
            if not fi:
                continue
            src = _cached_read(path)
            if src is None:
                continue

            if fi.language == "python":
                fixes += self._check_imports(path, src, fi, public_api)
                fixes += self._check_dead_code(
                    path, src, fi, file_infos, fi_map, src_cache=src_cache
                )
                fixes += self._check_signature(path, src, fi)
            if charter is not None:
                fixes += self._check_charter(path, fi, graph, charter)
            if include_format and self._formatter():
                fixes.append(
                    ProposedFix(
                        "format",
                        path,
                        "File can be auto-formatted",
                        True,
                    )
                )
        return fixes

    # ── Import analysis (Python AST) ──────────────────────────────────────────────

    def _check_imports(
        self, path: str, src: str, fi: FileInfo, public_api: dict[str, str]
    ) -> list[ProposedFix]:
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return []

        imported_names: set[str] = set()
        import_lines: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_names.add(alias.asname or alias.name.split(".")[0])
                    import_lines[alias.asname or alias.name.split(".")[0]] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported_names.add(alias.asname or alias.name)
                    import_lines[alias.asname or alias.name] = node.lineno

        defined_names: set[str] = {fn.name for fn in fi.functions} | {cl.name for cl in fi.classes}

        used_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                used_names.add(node.attr)

        fixes: list[ProposedFix] = []
        # Missing imports
        for name in sorted(used_names - imported_names - defined_names):
            definer = public_api.get(name)
            if definer and definer != path:
                module = definer.rsplit(".py", 1)[0].replace("/", ".")
                fixes.append(
                    ProposedFix(
                        "missing_import",
                        path,
                        f"'{name}' is used but not imported; define it in '{definer}'",
                        True,
                        name=name,
                        suggested=f"from {module} import {name}",
                    )
                )
        # Unused imports
        for name in sorted(imported_names - used_names - defined_names):
            fixes.append(
                ProposedFix(
                    "unused_import",
                    path,
                    f"Import '{name}' is never referenced",
                    True,
                    name=name,
                    line=import_lines.get(name, 0),
                )
            )
        return fixes

    # ── Dead code (referenced nowhere in the project) ─────────────────────────────

    def _check_dead_code(
        self,
        path: str,
        src: str,
        fi: FileInfo,
        file_infos: list[FileInfo],
        fi_map: dict[str, FileInfo],
        src_cache: dict[str, str] | None = None,
    ) -> list[ProposedFix]:
        fixes: list[ProposedFix] = []
        # Map name -> def line span so we can exclude the definition itself
        # when searching for *references* within the same file.
        span: dict[str, tuple[int, int]] = {}
        for f in fi.functions:
            span[f.name] = (getattr(f, "line", 1), getattr(f, "end_line", getattr(f, "line", 1)))
        for c in fi.classes:
            span[c.name] = (getattr(c, "line", 1), getattr(c, "end_line", getattr(c, "line", 1)))
        candidates = list(span)
        # Skip likely entry points (invoked externally, not within the project).
        entry_names = {"main", "run", "__main__"}
        candidates = [n for n in candidates if n not in entry_names and not n.startswith("__")]

        # Read every other file's source exactly once for this whole method call
        # (shared across all candidate symbols), instead of once per symbol.
        # Uses the caller-provided cache when available so it's shared across
        # the *entire* analyze_change() call too, not just this one file.
        cache = src_cache if src_cache is not None else {}
        other_sources: dict[str, str] = {}
        for other in file_infos:
            if other.path in cache:
                other_sources[other.path] = cache[other.path]
                continue
            src_o = self._read(other.path)
            if src_o is None:
                continue
            cache[other.path] = src_o
            other_sources[other.path] = src_o

        for name in candidates:
            # Search every file; for the defining file, blank out the def lines
            # so the definition does not count as a reference.
            referenced = False
            for other_path, src_o in other_sources.items():
                if other_path == path:
                    lines = src_o.splitlines()
                    lo, hi = span.get(name, (0, 0))
                    for ln in range(lo - 1, hi):
                        if 0 <= ln < len(lines):
                            lines[ln] = ""
                    src_o = "\n".join(lines)
                if _word_in_source(name, src_o):
                    referenced = True
                    break
            if not referenced:
                # Find the def line for context.
                line = 0
                for fn in fi.functions:
                    if fn.name == name:
                        line = getattr(fn, "line", 0)
                for cl in fi.classes:
                    if cl.name == name:
                        line = getattr(cl, "line", 0)
                fixes.append(
                    ProposedFix(
                        "dead_code",
                        path,
                        f"'{name}' is defined but referenced nowhere in the project",
                        True,
                        name=name,
                        line=line,
                    )
                )
        return fixes

    # ── Signature change → caller update ───────────────────────────────────────────

    def _check_signature(self, path: str, src: str, fi: FileInfo) -> list[ProposedFix]:
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return []

        current: dict[str, list[str]] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                params = [a.arg for a in args.args]
                params += [a.arg for a in args.kwonlyargs]
                if args.vararg:
                    params.append("*" + args.vararg.arg)
                if args.kwarg:
                    params.append("**" + args.kwarg.arg)
                current[node.name] = params

        baseline = self._load_baseline().get(path, {})
        if not baseline:
            self._store_baseline({path: current})
            return []

        fixes: list[ProposedFix] = []
        for name, params in current.items():
            if name in baseline and baseline[name] != params:
                callers = self._find_callers(path, name)
                fixes.append(
                    ProposedFix(
                        "signature_callers",
                        path,
                        f"'{name}' signature changed ({baseline[name]} → {params}); "
                        f"review {len(callers)} caller(s)",
                        False,
                        name=name,
                        callers=callers,
                    )
                )
        # Update baseline for next run.
        self._store_baseline({path: current})
        return fixes

    def _find_callers(self, path: str, name: str) -> list[str]:
        """Files (other than path) that contain a call site '<name>('."""
        callers: list[str] = []
        # Use the import graph to narrow the search to importers.
        from patchi.core.brain.import_graph import build_import_graph

        try:
            graph = build_import_graph(self.root)
            candidates = set(graph.reverse.get(path, set()))
            candidates |= graph.get_transitive_dependents(path)
        except Exception as e:
            _log.warning("ProactiveAgent._find_callers failed: %s", e)
            candidates = set()
        # Fall back to a whole-project textual scan if no graph.
        if not candidates:
            from patchi.core.brain.scanner import FileScanner

            try:
                candidates = {fi.path for fi in FileScanner(self.root).scan()}
            except Exception as e:
                _log.warning("ProactiveAgent._find_callers failed: %s", e)
                candidates = set()
        for c in candidates:
            if c == path:
                continue
            if re.search(rf"(?<![\w.]){re.escape(name)}\s*\(", self._read(c) or ""):
                callers.append(c)
        return sorted(callers)

    # ── Charter check on the changed file ──────────────────────────────────────────

    def _check_charter(
        self, path: str, fi: FileInfo, graph: ImportGraph | None, charter: object
    ) -> list[ProposedFix]:
        from patchi.core.brain.charter import _matches_boundary

        boundaries = getattr(charter, "boundaries", [])
        if not boundaries:
            return []
        sub = _classify_subsystem(_module_of(path))
        # Subsystems this file imports.
        imported_subs: set[str] = set()
        if graph is not None:
            for tgt in graph.edges.get(path, set()):
                imported_subs.add(_classify_subsystem(_module_of(tgt)))
        fixes: list[ProposedFix] = []
        for b in boundaries:
            for imp in sorted(imported_subs):
                if _matches_boundary(sub, imp, b):
                    fixes.append(
                        ProposedFix(
                            "charter_violation",
                            path,
                            f"Change makes '{sub}' import '{imp}', violating charter "
                            f"'{b.get('from')} must not import {b.get('to')}'",
                            False,
                            name=f"{sub}→{imp}",
                        )
                    )
        return fixes

    # ── Application ────────────────────────────────────────────────────────────────

    @staticmethod
    def apply(fix: ProposedFix, root: Path, apply_unsafe: bool = False) -> bool:
        """Apply a single fix. Returns True if applied. Safe fixes only unless apply_unsafe."""
        if not fix.safe and not apply_unsafe:
            return False
        path = Path(root) / fix.file
        if not path.exists():
            return False

        if fix.fix_type == "missing_import":
            return _apply_missing_import(path, fix.suggested)
        if fix.fix_type == "unused_import":
            return _apply_unused_import(path, fix.name, fix.line)
        if fix.fix_type == "dead_code":
            return _apply_dead_code(path, fix.name, fix.line)
        if fix.fix_type == "format":
            return _apply_format(path)
        # signature_callers / charter_violation are never auto-applied.
        return False

    # ── Helpers ─────────────────────────────────────────────────────────────────────

    def _read(self, path: str) -> str | None:
        try:
            return (self.root / path).read_text(encoding="utf-8")
        except Exception as e:
            _log.warning("ProactiveAgent._read failed: %s", e)
            return None

    def _formatter(self) -> str | None:
        for tool in ("ruff", "black"):
            if shutil.which(tool):
                return tool
        return None

    def _baseline_path(self) -> Path:
        return self.root / ".patchi" / "memory" / "proactive_signatures.json"

    def _load_baseline(self) -> dict:
        import json

        p = self._baseline_path()
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                _log.warning("ProactiveAgent._load_baseline failed: %s", e)
                return {}
        return {}

    def _store_baseline(self, update: dict) -> None:
        import json

        p = self._baseline_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        data = self._load_baseline()
        data.update(update)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ── Low-level text edits ─────────────────────────────────────────────────────────


def _write_guarded(path: Path, text: str) -> bool:
    """Write file content, refusing to wipe a file to empty/whitespace.

    Guards the auto-apply path so a 'safe' fix can never destroy a file's
    contents (e.g. removing the only top-level definition as 'dead code').
    """
    if not text.strip():
        return False
    path.write_text(text, encoding="utf-8")
    return True


def _apply_missing_import(path: Path, import_line: str) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()
    # Insert after the last existing import, else at the top (after docstring).
    insert_at = 0
    last_import = -1
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(("import ", "from ")):
            last_import = i
        elif stripped and not stripped.startswith("#"):
            break
    insert_at = last_import + 1 if last_import >= 0 else 0
    if any(ln.strip() == import_line for ln in lines):
        return False  # already present
    lines.insert(insert_at, import_line)
    return _write_guarded(path, "\n".join(lines) + "\n")


def _apply_unused_import(path: Path, name: str, line: int) -> bool:
    lines = path.read_text(encoding="utf-8").splitlines()
    target = line - 1 if line > 0 else None
    if target is not None and 0 <= target < len(lines) and name in lines[target]:
        del lines[target]
        return _write_guarded(path, "\n".join(lines) + "\n")
    # Fallback: remove first import line containing the name.
    for i, line in enumerate(lines):
        if re.search(
            rf"(^|\b)(import\s+.*\b{re.escape(name)}\b|from\s+\S+\s+import\s+.*\b{re.escape(name)}\b)",
            line,
        ):
            del lines[i]
            return _write_guarded(path, "\n".join(lines) + "\n")
    return False


def _apply_dead_code(path: Path, name: str, line: int) -> bool:
    """Remove the top-level def block for ``name`` (best-effort, safe-only behind flag)."""
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False
    target = None
    for node in tree.body:
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == name
        ):
            target = node
            break
    if target is None:
        return False
    start = target.lineno - 1
    end = target.end_lineno  # 1-based inclusive
    lines = src.splitlines()
    # Safety: never remove the only top-level definition in a file.
    top_level_defs = [
        n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if len(top_level_defs) <= 1:
        return False
    del lines[start:end]
    # Drop a trailing blank line left behind.
    while start < len(lines) and lines[start].strip() == "":
        del lines[start]
    return _write_guarded(path, "\n".join(lines) + "\n")


def _apply_format(path: Path) -> bool:
    tool = shutil.which("ruff") or shutil.which("black")
    if not tool:
        return False
    try:
        subprocess.run([tool, "format", str(path)], check=False, capture_output=True, timeout=30)
        return True
    except Exception as e:
        _log.warning("_apply_format failed: %s", e)
        return False


def run_proactive(
    root: Path,
    files: list[str],
    apply: bool = False,
    unsafe: bool = False,
    include_format: bool = True,
) -> dict:
    """
    High-level entry point used by `p auto` and watch mode.

    Scans project context, proposes proactive fixes for the given changed files,
    optionally applies the safe ones, and honours learned rejections
    (see patchi.core.brain.learning — the Learning Brain).

    Returns a structured result:
        {
            "fixes":        [ProposedFix] not suppressed,
            "applied":      [ProposedFix] actually applied,
            "escalated":    [ProposedFix] unsafe (need human/Governor review),
            "skipped":      [ProposedFix] safe but not applied (apply=False),
            "suppressed":   [ProposedFix] hidden because the user rejected them,
        }
    """
    from patchi.core.brain.charter import load_charter
    from patchi.core.brain.import_graph import build_import_graph
    from patchi.core.brain.scanner import FileScanner

    scanner = FileScanner(root)
    file_infos = scanner.scan()
    graph = build_import_graph(root)
    charter = load_charter(root)
    agent = ProactiveAgent(root)
    all_fixes = agent.analyze_change(
        files, file_infos, graph, charter, include_format=include_format
    )

    # Phase 5 — Learning Brain: don't propose fix types the user rejects.
    suppressed = [f for f in all_fixes if not learning.should_suggest(f.fix_type, root)]
    active = [f for f in all_fixes if f not in suppressed]

    applied, escalated, skipped = [], [], []
    for f in active:
        if apply and ProactiveAgent.apply(f, root, apply_unsafe=unsafe):
            applied.append(f)
            learning.record_acceptance(f.fix_type, "ProactiveAgent", root)
        elif not f.safe:
            escalated.append(f)
        else:
            skipped.append(f)

    return {
        "fixes": active,
        "applied": applied,
        "escalated": escalated,
        "skipped": skipped,
        "suppressed": suppressed,
    }


def escalate_to_governor(root: Path, fix: ProposedFix) -> None:
    """
    Surface an unsafe fix (e.g. charter violation) to human review by recording
    it as an open issue. This is the lightweight Governor escalation sink — the
    issue shows up in the unified findings/issues list for both humans and ants.
    """
    from patchi.core import memory as mem

    mem.save_issue(
        {
            "source": "ProactiveAgent",
            "fix_type": fix.fix_type,
            "file": fix.file,
            "name": fix.name,
            "description": fix.description,
            "severity": "high" if fix.fix_type == "charter_violation" else "medium",
        },
        root,
    )


# ── Prioritized Fix List (Dream Assistant spec) ──────────────────────────────────

# Lower number = higher priority (fix first). Charter/contract breaches and
# breaking changes rank above cosmetic cleanups.
_FIX_PRIORITY: dict[str, int] = {
    "charter_violation": 1,
    "signature_callers": 2,
    "missing_import": 3,
    "dead_code": 4,
    "unused_import": 5,
    "format": 6,
}


def rank_fixes(fixes: list[ProposedFix]) -> list[ProposedFix]:
    """Return fixes sorted by priority (high→low), then safe-before-unsafe."""
    return sorted(
        fixes,
        key=lambda f: (_FIX_PRIORITY.get(f.fix_type, 9), 0 if f.safe else 1, f.file, f.name),
    )


def build_fix_list(
    root: Path,
    area: str | None = None,
    include_format: bool = False,
    include_missing_import: bool = False,
) -> list[ProposedFix]:
    """
    Propose fixes across the whole project (or an area) and return them ranked
    — the standalone "Prioritized Fix List" view.

    ``missing_import`` is excluded by default: across a whole repo every
    cross-module symbol reads as "used but not imported in this file", which is
    noise here (it is meaningful only for *changed* files in ``run_proactive``).
    """
    from patchi.core.brain.charter import load_charter
    from patchi.core.brain.import_graph import build_import_graph
    from patchi.core.brain.scanner import FileScanner

    root = Path(root)
    scanner = FileScanner(root)
    file_infos = scanner.scan()
    graph = build_import_graph(root)
    charter = load_charter(root)
    agent = ProactiveAgent(root)

    if area:
        area_rel = str(area).rstrip("/\\")
        files = [
            fi.path
            for fi in file_infos
            if fi.path == area_rel or fi.path.startswith(area_rel + "/")
        ]
    else:
        files = [fi.path for fi in file_infos]

    fixes = agent.analyze_change(files, file_infos, graph, charter, include_format=include_format)
    # Honour learned rejections (Phase 5) for the list too.
    visible = [f for f in fixes if learning.should_suggest(f.fix_type, root)]
    if not include_missing_import:
        visible = [f for f in visible if f.fix_type != "missing_import"]
    return rank_fixes(visible)
