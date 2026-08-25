"""
External tool runners for symbol-level dead code detection.

Each runner invokes a language-specific tool and normalizes its output
into a list of dicts with keys: symbol, file, line, tool, confidence.

Tools:
  - vulture (Python) — already a dependency
  - ts-prune (JS/TS) — npm package, optional
  - deadcode (Python) — alternative to vulture
  - ruff (Python) — unused imports via F401
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patchi.core.brain.file_corpus import FileCorpus


def run_vulture(root: Path, min_confidence: int = 60) -> list[dict]:
    """Run vulture on a Python project and return unused symbols."""
    if not shutil.which("vulture"):
        return []
    try:
        proc = subprocess.run(
            ["vulture", str(root), "--min-confidence", str(min_confidence), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode not in (0, 1):
            return []
        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                results.append(
                    {
                        "symbol": entry.get("name", ""),
                        "file": entry.get("filename", ""),
                        "line": entry.get("lineno", 0),
                        "tool": "vulture",
                        "confidence": entry.get("confidence", min_confidence),
                    }
                )
            except json.JSONDecodeError:
                continue
        return results
    except (subprocess.TimeoutExpired, Exception):
        return []


def run_ruff_unused_imports(root: Path) -> list[dict]:
    """Run ruff to find unused imports (F401) across the project."""
    if not shutil.which("ruff"):
        return []
    try:
        proc = subprocess.run(
            ["ruff", "check", str(root), "--select=F401", "--output-format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("code") == "F401":
                    results.append(
                        {
                            "symbol": entry.get("message", "").split("'")[1]
                            if "'" in entry.get("message", "")
                            else "",
                            "file": entry.get("filename", ""),
                            "line": entry.get("location", {}).get("row", 0),
                            "tool": "ruff",
                            "confidence": 90,
                        }
                    )
            except (json.JSONDecodeError, IndexError):
                continue
        return results
    except (subprocess.TimeoutExpired, Exception):
        return []


def run_ts_prune(root: Path) -> list[dict]:
    """Run ts-prune on a TypeScript project to find unused exports."""
    if not shutil.which("npx"):
        return []
    pkg_json = root / "package.json"
    if not pkg_json.exists():
        return []
    try:
        proc = subprocess.run(
            ["npx", "--yes", "ts-prune", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(root),
        )
        results = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("isDefault", False):
                    continue
                results.append(
                    {
                        "symbol": entry.get("symbol", ""),
                        "file": entry.get("file", ""),
                        "line": 0,
                        "tool": "ts-prune",
                        "confidence": 70,
                    }
                )
            except json.JSONDecodeError:
                continue
        return results
    except (subprocess.TimeoutExpired, Exception):
        return []


def detect_and_run(root: Path, corpus: FileCorpus | None = None) -> list[dict]:
    """Auto-detect project type and run all applicable dead code tools."""
    results: list[dict] = []

    has_python = any(corpus.by_ext(".py")) if corpus else any(root.rglob("*.py"))
    has_ts = (
        any(corpus.by_ext(".ts", ".tsx"))
        if corpus
        else any(root.rglob("*.ts")) or any(root.rglob("*.tsx"))
    )

    if has_python:
        results.extend(run_vulture(root))
        results.extend(run_ruff_unused_imports(root))

    if has_ts:
        results.extend(run_ts_prune(root))

    return results
