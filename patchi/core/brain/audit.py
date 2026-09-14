"""
Drift Detector + Plan-vs-Built Report Card (Dream Assistant spec, priority #2).

The agent (and the developer) declare *intent* — a Plan: which layers exist,
what the charter is, what the codebase currently looks like. Later, `p audit`
re-scans the *actual* built state and reports the gap between Plan and Built.

This is deliberately additive: it snapshots the current memory (layers, charter,
scan results) as a Plan and diffs it against the live state.

Usage:
  p audit save [--intent "..."]   — snapshot current state as the agreed Plan
  p audit [--no-scan]             — Plan-vs-Built report card + drift
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

_PLAN_FILE = ".patchi/plan.json"


_log = logging.getLogger("patchi.brain.audit")


def _snapshot_scope(root: Path) -> dict:
    """
    Capture the REAL scope of the codebase: for every source file its language,
    exported symbols (functions/classes/exports), and a content hash. This is
    what makes the Drift Detector a true scope diff, not just a finding-count
    proxy.
    """
    from patchi.core.brain.scanner import FileScanner

    try:
        fis = FileScanner(root).scan()
    except Exception as e:
        _log.warning("_snapshot_scope failed: %s", e)
        return {}
    scope: dict[str, dict] = {}
    for fi in fis:
        if fi.error:
            continue
        try:
            data = (Path(root) / fi.path).read_bytes()
            h = hashlib.sha256(data).hexdigest()[:16]
        except Exception as e:
            _log.warning("_snapshot_scope failed: %s", e)
            h = ""
        syms = sorted({f.name for f in fi.functions} | {c.name for c in fi.classes} | set(fi.exports))
        scope[fi.path] = {"lang": fi.language.value, "symbols": syms, "hash": h}
    return scope


def _diff_scope(plan_scope: dict, cur_scope: dict) -> dict:
    """Real file/symbol scope diff between the agreed Plan and the built state."""
    plan_files = set(plan_scope)
    cur_files = set(cur_scope)
    added = sorted(cur_files - plan_files)
    removed = sorted(plan_files - cur_files)
    modified = []
    for f in sorted(plan_files & cur_files):
        p = plan_scope[f]
        c = cur_scope[f]
        if p.get("hash") == c.get("hash"):
            continue
        added_sym = sorted(set(c.get("symbols", [])) - set(p.get("symbols", [])))
        removed_sym = sorted(set(p.get("symbols", [])) - set(c.get("symbols", [])))
        modified.append(
            {
                "file": f,
                "symbols_added": added_sym,
                "symbols_removed": removed_sym,
                "symbols_unchanged": sorted(set(p.get("symbols", [])) & set(c.get("symbols", []))),
            }
        )
    return {
        "added_files": added,
        "removed_files": removed,
        "modified_files": modified,
        "added_count": len(added),
        "removed_count": len(removed),
        "modified_count": len(modified),
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _count_findings(result: dict) -> int:
    """Recursively count concrete findings inside one scanner result."""
    if not isinstance(result, dict):
        return 0
    total = 0
    for key, val in result.items():
        if key in ("timestamp", "scanned_at", "layer", "name"):
            continue
        if key == "findings" and isinstance(val, list):
            total += len([f for f in val if f])
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and (item.get("findings") or item.get("issues")):
                    total += len(item.get("findings") or item.get("issues") or [])
                elif isinstance(item, dict):
                    total += _count_findings(item)
        elif isinstance(val, dict):
            total += _count_findings(val)
    return total


def _charter_violations(scans: dict) -> int:
    cg = scans.get("CharterGuard", {})
    if isinstance(cg, dict):
        return len(cg.get("findings", []) or [])
    return 0


def _snapshot_state(root: Path) -> dict:
    from patchi.core import memory as mem

    charter = mem.get_charter(root) or {}
    layers = mem.get_layers(root) or {}
    scans = mem.get_scan_results(root) or {}
    scan_summary = {
        name: {
            "finding_count": _count_findings(res),
            "timestamp": (res.get("timestamp") if isinstance(res, dict) else None),
        }
        for name, res in scans.items()
    }
    return {
        "layers": layers,
        "charter": charter,
        "scan_summary": scan_summary,
        "charter_violations": _charter_violations(scans),
        "total_findings": sum(v["finding_count"] for v in scan_summary.values()),
    }


def save_plan(root: Path, intent: str | None = None) -> dict:
    """Snapshot the current state (including real scope) as the agreed Plan."""
    root = Path(root)
    state = _snapshot_state(root)
    plan = {
        "saved_at": _now(),
        "intent": intent or "",
        **state,
        "scope": _snapshot_scope(root),
    }
    p = root / _PLAN_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(plan, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)
    return plan


def load_plan(root: Path) -> dict | None:
    p = Path(root) / _PLAN_FILE
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        _log.warning("load_plan failed: %s", e)
        return None


def compute_drift(root: Path, scans: dict | None = None) -> dict:
    """
    Diff the agreed Plan against the live built state.

    scans: optional injectable current scan results (for tests).
    """
    root = Path(root)
    plan = load_plan(root)
    if not plan:
        return {"has_plan": False}

    current = _snapshot_state(root) if scans is None else _summarize(scans)
    cur_scope = _snapshot_scope(root)

    plan_layers = set((plan.get("layers") or {}).keys())
    cur_layers = set((current.get("layers") or {}).keys())
    added = sorted(cur_layers - plan_layers)
    removed = sorted(plan_layers - cur_layers)
    unchanged = sorted(plan_layers & cur_layers)

    scope_diff = _diff_scope(plan.get("scope", {}) or {}, cur_scope)

    drift = {
        "has_plan": True,
        "saved_at": plan.get("saved_at"),
        "intent": plan.get("intent", ""),
        "layers_added": added,
        "layers_removed": removed,
        "layers_unchanged": unchanged,
        "plan_total_findings": plan.get("total_findings", 0),
        "built_total_findings": current.get("total_findings", 0),
        "new_findings": max(0, current.get("total_findings", 0) - plan.get("total_findings", 0)),
        "plan_charter_violations": plan.get("charter_violations", 0),
        "built_charter_violations": current.get("charter_violations", 0),
        "new_charter_violations": max(0, current.get("charter_violations", 0) - plan.get("charter_violations", 0)),
        "per_scanner": _diff_scanners(plan.get("scan_summary", {}), current.get("scan_summary", {})),
        "scope_diff": scope_diff,
    }
    drift["clean"] = (
        not added
        and not removed
        and drift["new_findings"] == 0
        and drift["new_charter_violations"] == 0
        and scope_diff["added_count"] == 0
        and scope_diff["removed_count"] == 0
        and scope_diff["modified_count"] == 0
    )
    return drift


def _summarize(scans: dict) -> dict:
    scan_summary = {name: {"finding_count": _count_findings(res), "timestamp": None} for name, res in scans.items()}
    return {
        "layers": {},
        "charter": {},
        "scan_summary": scan_summary,
        "charter_violations": _charter_violations(scans),
        "total_findings": sum(v["finding_count"] for v in scan_summary.values()),
    }


def _diff_scanners(plan_summary: dict, cur_summary: dict) -> list[dict]:
    rows = []
    all_names = sorted(set(plan_summary) | set(cur_summary))
    for name in all_names:
        plan_c = plan_summary.get(name, {}).get("finding_count", 0)
        cur_c = cur_summary.get(name, {}).get("finding_count", 0)
        delta = cur_c - plan_c
        rows.append({"scanner": name, "plan": plan_c, "built": cur_c, "delta": delta})
    return rows


def report_card(root: Path, run_scan: bool = True) -> dict:
    """
    Plan-vs-Built Report Card. Re-scans (unless --no-scan) then computes drift
    and a plain-language summary.
    """
    root = Path(root)
    if run_scan:
        try:
            from patchi.core.brain.brain import Brain

            Brain(root).scan()
        except Exception as e:
            _log.warning("report_card failed: %s", e)
    drift = compute_drift(root)
    if not drift.get("has_plan"):
        return {"has_plan": False, "summary": "No Plan saved. Run `p audit save` first."}

    lines = [f"Plan saved at {drift['saved_at']}"]
    if drift.get("intent"):
        lines.append(f"Intent: {drift['intent']}")
    if drift["layers_added"]:
        lines.append(f"  + Layers built beyond plan: {', '.join(drift['layers_added'])}")
    if drift["layers_removed"]:
        lines.append(f"  - Layers in plan but missing: {', '.join(drift['layers_removed'])}")
    sd = drift.get("scope_diff", {}) or {}
    if sd.get("added_files"):
        lines.append(
            f"  + Files added beyond plan ({sd['added_count']}): "
            f"{', '.join(f for f in sd['added_files'][:8])}" + (" …" if sd["added_count"] > 8 else "")
        )
    if sd.get("removed_files"):
        lines.append(
            f"  - Files removed vs plan ({sd['removed_count']}): "
            f"{', '.join(f for f in sd['removed_files'][:8])}" + (" …" if sd["removed_count"] > 8 else "")
        )
    if sd.get("modified_files"):
        lines.append(f"  ~ Files changed vs plan ({sd['modified_count']}):")
        for m in sd["modified_files"][:8]:
            bits = []
            if m["symbols_added"]:
                bits.append(f"+{len(m['symbols_added'])} sym")
            if m["symbols_removed"]:
                bits.append(f"-{len(m['symbols_removed'])} sym")
            if not bits:
                bits.append("content changed")
            lines.append(f"      • {m['file']}  ({', '.join(bits)})")
    lines.append(
        f"  Findings: plan {drift['plan_total_findings']} -> built {drift['built_total_findings']} "
        f"({drift['new_findings']} new)"
    )
    if drift["new_charter_violations"]:
        lines.append(f"  Charter violations: {drift['new_charter_violations']} new")
    for row in drift["per_scanner"]:
        if row["delta"]:
            lines.append(f"    • {row['scanner']}: {row['plan']} -> {row['built']} ({row['delta']:+d})")
    status = "ON PLAN ✅" if drift["clean"] else "DRIFT DETECTED ⚠️"
    lines.insert(0, f"Plan-vs-Built: {status}")
    drift["summary"] = "\n".join(lines)
    return drift


def drift_vs_plan_file(root: Path, plan_file: str | Path) -> dict:
    """
    Audit the built state against an externally supplied plan/spec file
    (the `p audit --plan-file` path). The file is treated as the agreed Plan
    and diffed against the live state.
    """
    root = Path(root)
    path = Path(plan_file)
    if not path.exists():
        return {"has_plan": False, "error": f"Plan file not found: {path}"}
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return {"has_plan": False, "error": f"Could not parse plan file: {e}"}

    current = _snapshot_state(root)
    cur_scope = _snapshot_scope(root)
    plan_layers = set((plan.get("layers") or {}).keys())
    cur_layers = set((current.get("layers") or {}).keys())
    plan_total = plan.get("total_findings", 0)
    cur_total = current.get("total_findings", 0)
    plan_charter = plan.get("charter_violations", 0)
    cur_charter = current.get("charter_violations", 0)

    plan_summary = plan.get("scan_summary", {})
    cur_summary = current.get("scan_summary", {})

    drift = {
        "has_plan": True,
        "from_file": str(path),
        "intent": plan.get("intent", ""),
        "layers_added": sorted(cur_layers - plan_layers),
        "layers_removed": sorted(plan_layers - cur_layers),
        "plan_total_findings": plan_total,
        "built_total_findings": cur_total,
        "new_findings": max(0, cur_total - plan_total),
        "new_charter_violations": max(0, cur_charter - plan_charter),
        "per_scanner": _diff_scanners(plan_summary, cur_summary),
        "scope_diff": _diff_scope(plan.get("scope", {}) or {}, cur_scope),
    }
    drift["clean"] = (
        not drift["layers_added"]
        and not drift["layers_removed"]
        and drift["new_findings"] == 0
        and drift["new_charter_violations"] == 0
    )
    status = "ON PLAN ✅" if drift["clean"] else "DRIFT DETECTED ⚠️"
    lines = [f"Plan-vs-Built (vs {path.name}): {status}"]
    if drift["intent"]:
        lines.append(f"Intent: {drift['intent']}")
    if drift["layers_added"]:
        lines.append(f"  + Layers beyond plan: {', '.join(drift['layers_added'])}")
    if drift["layers_removed"]:
        lines.append(f"  - Layers missing vs plan: {', '.join(drift['layers_removed'])}")
    lines.append(f"  Findings: plan {plan_total} -> built {cur_total} ({drift['new_findings']} new)")
    if drift["new_charter_violations"]:
        lines.append(f"  Charter violations: {drift['new_charter_violations']} new")
    drift["summary"] = "\n".join(lines)
    return drift
