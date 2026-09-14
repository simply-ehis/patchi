"""
Risk Heatmap §9.1.3 — file map colored by bug-prone score.

Score per file: findings * 10 + churn * 2 + (size_kb / 10) + complexity_hint.
Color intensity mapped to folder tree for web D3 treemap.

Usage:
  from patchi.core.brain.heatmap import build_heatmap
  data = build_heatmap(root)  # {name, children, value, severity}
  # CLI: p heatmap | p heatmap --json
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path

from patchi.core import memory as mem

_log = logging.getLogger("patchi.brain.heatmap")


def _git_churn(root: Path, rel: str) -> int:
    try:
        import subprocess

        out = subprocess.run(
            ["git", "log", "--oneline", "--", rel],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            cwd=str(root),
        )
        if out.returncode == 0:
            return len([line for line in out.stdout.splitlines() if line.strip()])
    except Exception as exc:  # noqa: BLE001
        _log.debug("churn %s failed: %s", rel, exc)
    return 0


def build_heatmap(root: Path) -> dict:
    scans = mem.get_scan_results(root) or {}
    # findings per file
    per_file: dict[str, int] = defaultdict(int)
    sev_max: dict[str, str] = {}
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for data in scans.values():
        for f in data.get("findings", []) if isinstance(data, dict) else []:
            fp = f.get("file", "")
            if not fp:
                continue
            per_file[fp] += 1
            sev = f.get("severity", "low")
            if order.get(sev, 0) > order.get(sev_max.get(fp, "info"), 0):
                sev_max[fp] = sev

    # file sizes for complexity hint
    from patchi.core.brain.file_corpus import FileCorpus

    corpus = FileCorpus(root)
    size_map = {e.path: e.size_bytes for e in corpus.files()}

    # build tree
    tree: dict = {}
    for rel, cnt in per_file.items():
        parts = rel.split("/")
        cur = tree
        for seg in parts[:-1]:
            cur = cur.setdefault(seg, {})
        leaf = parts[-1]
        churn = _git_churn(root, rel) if cnt else 0
        size_kb = size_map.get(rel, 0) / 1024
        score = cnt * 10 + churn * 2 + size_kb / 10
        cur[leaf] = {
            "_value": round(score, 1),
            "_severity": sev_max.get(rel, "low"),
            "_findings": cnt,
        }

    def to_children(d: dict, name: str = "root") -> dict:
        children = []
        for k, v in sorted(d.items()):
            if isinstance(v, dict) and "_value" in v:
                children.append(
                    {
                        "name": k,
                        "value": v["_value"],
                        "severity": v["_severity"],
                        "findings": v["_findings"],
                    }
                )
            elif isinstance(v, dict):
                sub = to_children(v, k)
                if sub["children"]:
                    total = sum(c.get("value", 0) for c in sub["children"])
                    sub["value"] = round(total, 1)
                    children.append(sub)
        return {"name": name, "children": children}

    root_node = to_children(tree)
    # top hotspots
    flat = []

    def collect(node, prefix=""):
        for ch in node.get("children", []):
            path = f"{prefix}/{ch['name']}" if prefix else ch["name"]
            if "children" in ch:
                collect(ch, path)
            else:
                flat.append((path, ch["value"], ch["severity"]))

    collect(root_node)
    flat.sort(key=lambda x: -x[1])
    return {
        "tree": root_node,
        "hotspots": [{"file": p, "score": s, "severity": sev} for p, s, sev in flat[:20]],
        "total_files": len(per_file),
    }
