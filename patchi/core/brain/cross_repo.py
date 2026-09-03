"""
CrossRepo §11.3 — multi-repo index for shared library drift.

Indexes multiple repo roots (siblings or explicit list) and compares dependency versions + API usage.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

_log = logging.getLogger("patchi.brain.cross_repo")

def index_repos(roots: list[Path]) -> dict:
    idx={}
    for r in roots:
        try:
            from patchi.core.brain.file_corpus import FileCorpus
            corpus=FileCorpus(r)
            idx[str(r)]={"files": len(list(corpus.files())), "deps": _deps(r)}
        except Exception:
            idx[str(r)]={"files":0,"deps":{}}
    return idx

def _deps(root: Path) -> dict:
    """Parsed {package: version} per manifest (not raw text)."""
    deps: dict[str, dict[str, str]] = {}
    try:
        p = root / "package.json"
        if p.exists():
            pkg = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            merged = {}
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                for name, ver in (pkg.get(section) or {}).items():
                    merged[str(name)] = str(ver)
            if merged:
                deps["package.json"] = merged
    except Exception as _exc:
        _log.debug("package.json parse failed: %s", _exc)
    try:
        p = root / "requirements.txt"
        if p.exists():
            parsed = {}
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-", " ")):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:==|>=|<=|~=|!=|>|<)?\s*([^;\s]*)", line)
                if m:
                    parsed[m.group(1).lower()] = m.group(2) or "unpinned"
            if parsed:
                deps["requirements.txt"] = parsed
    except Exception as _exc:
        _log.debug("requirements parse failed: %s", _exc)
    try:
        p = root / "go.mod"
        if p.exists():
            parsed = {}
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^\s*([a-z0-9./\-_]+)\s+(v[\w.+\-]+)", line.strip(), re.I)
                if m and "module" not in line and "go " != line[:3]:
                    parsed[m.group(1)] = m.group(2)
            if parsed:
                deps["go.mod"] = parsed
    except Exception as _exc:
        _log.debug("go.mod parse failed: %s", _exc)
    try:
        p = root / "Cargo.toml"
        if p.exists():
            parsed = {}
            in_deps = False
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if s.startswith("["):
                    in_deps = "dependencies" in s
                    continue
                if in_deps:
                    m = re.match(r"^([A-Za-z0-9_\-]+)\s*=\s*\"?([^\"]*)\"?", s)
                    if m:
                        parsed[m.group(1)] = m.group(2) or "unpinned"
            if parsed:
                deps["Cargo.toml"] = parsed
    except Exception as _exc:
        _log.debug("Cargo.toml parse failed: %s", _exc)
    return deps

def drift_report(roots: list[Path]) -> dict:
    idx=index_repos(roots)
    # real version drift: same package, different versions across repos
    seen: dict[str, dict[str, list]] = {}
    for r, data in idx.items():
        for pkgs in data.get("deps", {}).values():
            if not isinstance(pkgs, dict):
                continue
            for name, ver in pkgs.items():
                seen.setdefault(name, {}).setdefault(str(ver), []).append(r)
    drift=[]
    for name, versions in seen.items():
        if len(versions) > 1:
            drift.append({"package": name[:80],
                          "versions": {v: rs[:3] for v, rs in versions.items()}})
    return {"index": idx, "drift": drift[:10]}
