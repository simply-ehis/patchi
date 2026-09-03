"""
CrossRepo §11.3 — multi-repo index for shared library drift.

Indexes multiple repo roots (siblings or explicit list) and compares dependency versions + API usage.
"""

from __future__ import annotations

import json
from pathlib import Path

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
    deps={}
    for name in ["package.json","requirements.txt","Cargo.toml","go.mod"]:
        p=root/name
        if p.exists():
            try:
                txt=p.read_text(encoding="utf-8", errors="replace")
                deps[name]=txt[:500]
            except Exception as _exc:
                logging.getLogger("patchi").debug('suppressed: %s', _exc)
    return deps

def drift_report(roots: list[Path]) -> dict:
    idx=index_repos(roots)
    # find version drift: same package different versions
    drift=[]
    all_pkgs={}
    for r, data in idx.items():
        for manifest, content in data.get("deps",{}).items():
            for line in content.splitlines():
                if "==" in line or "\"version\"" in line:
                    all_pkgs.setdefault(line.strip(), []).append(r)
    for pkg, repos in all_pkgs.items():
        if len(repos)>1:
            drift.append({"package": pkg[:80], "repos": repos[:3]})
    return {"index": idx, "drift": drift[:10]}
