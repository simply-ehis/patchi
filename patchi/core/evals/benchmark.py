"""Detection benchmark harness — the sales sheet.

Runs real detector agents against labeled vulnerable/clean cases and scores
what a customer actually buys: per-category detection rate + clean-trap FP
rate. Fully offline (no model, no network) so it runs in CI.

Layout: evals/benchmarks/<name>/manifest.json — cases carry inline `code`,
materialized to a tmp project at run time. One file per benchmark, fully
reviewable, no seed-file sprawl.

Honesty rules (same as p eval): a skipped agent is never a pass — if a
benchmark's agents can't run, the suite reports partial with reason.
Extras on vuln files are listed for FP review, never silently dropped.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

_BENCH_DIR = Path(__file__).resolve().parent.parent.parent.parent / "evals" / "benchmarks"


def list_benchmarks() -> list[str]:
    """Names of available detection benchmarks."""
    if not _BENCH_DIR.is_dir():
        return []
    return sorted(p.name for p in _BENCH_DIR.iterdir() if (p / "manifest.json").is_file())


def load_manifest(name: str) -> dict:
    """Load and minimally validate a benchmark manifest."""
    path = _BENCH_DIR / name / "manifest.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("cases"), list):
        raise ValueError(f"{name}/manifest.json: need {{..., cases: [...]}}")
    for case in data["cases"]:
        for key in ("id", "kind", "file", "code"):
            if key not in case:
                raise ValueError(f"{name}: case missing {key!r}: {case.get('id', '?')}")
        if case["kind"] not in ("vuln", "clean"):
            raise ValueError(f"{name}: case {case['id']} kind must be vuln|clean")
    return data


def _materialize(manifest: dict) -> Path:
    """Write case sources to a tmp project dir. Returns root."""
    root = Path(tempfile.mkdtemp(prefix="patchi-bench-"))
    for case in manifest["cases"]:
        dest = root / case["file"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(case["code"], encoding="utf-8")
    return root


def _run_agents(root: Path, agent_names: list[str]) -> tuple[list[dict], list[str]]:
    """Run named agents against root. Returns (findings, skipped_reasons).

    Findings are normalized to {file, type, cwe, severity, agent, line}.
    """
    import patchi.core.security.security_agents  # noqa: F401 — registers agents
    from patchi.core.agents.base import AgentInput, AgentStatus, get_agent

    findings: list[dict] = []
    skipped: list[str] = []
    for name in agent_names:
        cls = get_agent(name)
        if cls is None:
            skipped.append(f"{name}: not registered")
            continue
        inp = AgentInput(root=root, scope=[], brain={}, config={})
        try:
            res = cls().run(inp)
        except Exception as exc:
            skipped.append(f"{name}: crashed: {exc}")
            continue
        if res.status == AgentStatus.SKIPPED:
            skipped.append(f"{name}: {res.data.get('skip_reason', 'skipped')}")
            continue
        for f in res.findings or []:
            # Agents disagree on path shape (InjectionAgent: relative,
            # SecretScanner: absolute). Normalize to root-relative posix here
            # so matching never depends on which agent reported.
            raw_file = str(getattr(f, "file", "") or "")
            try:
                norm_file = Path(raw_file).relative_to(root).as_posix()
            except ValueError:
                norm_file = raw_file.replace("\\", "/")
            findings.append(
                {
                    "file": norm_file,
                    "type": str(getattr(f, "type", "") or ""),
                    "cwe": str(getattr(f, "cwe", "") or ""),
                    "severity": str(getattr(f, "severity", "") or ""),
                    "agent": name,
                    "line": getattr(f, "line", getattr(f, "line_start", 0)),
                }
            )
    return findings, skipped


_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(severity: str) -> int:
    return _SEV_RANK.get((severity or "").lower(), 0)


def _matches(case: dict, finding: dict) -> bool:
    """A finding counts for a vuln case: same file + expected type/CWE hit."""
    if finding["file"] != case["file"]:
        return False
    expect = case.get("expect", {}) or {}
    want_types = [t.lower() for t in (expect.get("type") or [])]
    want_cwes = [c.upper() for c in (expect.get("cwe") or [])]
    if not want_types and not want_cwes:
        return True
    got_type = finding["type"].lower()
    got_cwe = finding["cwe"].upper()
    if any(w in got_type for w in want_types):
        return True
    return bool(got_cwe) and got_cwe in want_cwes


def eval_benchmark(name: str) -> dict:
    """Run one detection benchmark. Returns a scorecard dict."""
    try:
        manifest = load_manifest(name)
    except Exception as exc:
        return {"suite": f"benchmark:{name}", "ok": False, "error": str(exc)}

    agents = manifest.get("agents", [])
    if not agents:
        return {"suite": f"benchmark:{name}", "ok": False, "error": "manifest declares no agents"}

    root = _materialize(manifest)
    findings, skipped = _run_agents(root, agents)

    details: list[dict] = []
    known_gaps: list[dict] = []
    for case in manifest["cases"]:
        on_file = [f for f in findings if f["file"] == case["file"]]
        entry: dict
        if case["kind"] == "vuln":
            hits = [f for f in on_file if _matches(case, f)]
            extras = [f for f in on_file if f not in hits]
            passed = bool(hits)
            entry = {
                "id": case["id"],
                "kind": "vuln",
                "category": case.get("category", "?"),
                "pass": passed,
                "hits": hits,
                "extra_findings": extras,
                "reason": "" if passed else "no finding matched expect",
            }
        else:
            # Severity-aware trap: LOW/INFO notes are review noise (listed,
            # non-failing); MEDIUM+ on clean code wastes analyst time and
            # fails. Per-case `allow_severity_up_to` overrides the default.
            threshold = _sev_rank(case.get("allow_severity_up_to", "low"))
            bad = [f for f in on_file if _sev_rank(f.get("severity", "")) > threshold]
            noise = [f for f in on_file if f not in bad]
            passed = not bad
            entry = {
                "id": case["id"],
                "kind": "clean",
                "category": case.get("category", "?"),
                "pass": passed,
                "hits": [],
                "extra_findings": bad,
                "noise": noise,
                "reason": "" if passed else f"{len(bad)} false positive(s) above {case.get('allow_severity_up_to', 'low')}",
            }
        # Documented misses drive future work without red fatigue: reported
        # separately, excluded from ok.
        if case.get("known_gap"):
            entry["known_gap"] = case.get("known_gap_reason", "")
            known_gaps.append(entry)
        else:
            details.append(entry)

    vuln = [d for d in details if d["kind"] == "vuln"]
    clean = [d for d in details if d["kind"] == "clean"]
    detected = sum(1 for d in vuln if d["pass"])
    fps = sum(1 for d in clean if not d["pass"])
    by_category: dict[str, dict] = {}
    for d in details:
        cat = d["category"]
        slot = by_category.setdefault(cat, {"vuln": 0, "detected": 0, "clean": 0, "fps": 0})
        if d["kind"] == "vuln":
            slot["vuln"] += 1
            if d["pass"]:
                slot["detected"] += 1
        else:
            slot["clean"] += 1
            if not d["pass"]:
                slot["fps"] += 1

    total = len(details)
    passed_n = sum(1 for d in details if d["pass"])
    ok: bool | None
    reason = ""
    if skipped:
        # Skip is never a pass: measurable but partial.
        ok = None if passed_n == total else False
        reason = "; ".join(skipped)
    else:
        ok = passed_n == total
    return {
        "suite": f"benchmark:{name}",
        "benchmark": name,
        "owasp": manifest.get("owasp", ""),
        "agents": agents,
        "cases": total,
        "passed": passed_n,
        "detection_rate": round(detected / len(vuln), 3) if vuln else 1.0,
        "clean_fp": fps,
        "clean_total": len(clean),
        "by_category": by_category,
        "known_gaps": known_gaps,
        "skipped_agents": skipped,
        "skip_reason": reason,
        "ok": ok,
        "failures": [d for d in details if not d["pass"]],
        "details": details,
    }
