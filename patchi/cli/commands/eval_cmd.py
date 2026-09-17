"""
Eval command — score the pipeline against the standing eval set (spec §5).

Usage:
    p eval              → all offline suites (gate + noise)
    p eval gate         → ConfidenceGate routing cases only
    p eval noise        → NoiseFilter cases only
    p eval benchmark [name] → detection benchmark(s): real agents vs
                              labeled vuln/clean cases (the sales sheet)
    p eval --json       → JSON output (CI-friendly)
    p eval --ci         → exit 1 when any suite fails
"""

from __future__ import annotations

import json

from patchi.cli.console import con
from patchi.core.config import require_project_root


def _skipped(name: str, reason: str) -> dict:
    return {"suite": name, "ok": None, "skipped": True, "reason": reason}


def _render(result: dict) -> None:
    suites = result["suites"]
    for name in ("gate", "noise"):
        s = suites.get(name)
        if not s or s.get("skipped"):
            continue
        mark = "PASS" if s["ok"] else "FAIL"
        con.print(f"[bold]{name}[/bold]  {s['passed']}/{s['cases']}  {mark}")
        for f in s.get("failures", []):
            con.print(f"  [red]✗ {f['id']}[/red] expected={f['expected']} actual={f['actual']}")
    gate = suites.get("gate") or {}
    if gate and not gate.get("skipped"):
        con.print(f"vuln recall={gate['vuln_recall']}  clean defend escapes={gate['clean_defend_escapes']}")
        # §4: per-tier calibration on screen, not just JSON.
        for tier, cal in (gate.get("tier_calibration") or {}).items():
            con.print(f"  tier {tier}: n={cal['n']} vuln_fraction={cal['vuln_fraction']} routing={cal['routing']}")
        th = gate.get("thresholds") or {}
        con.print(f"  thresholds: {th}")
    gen = suites.get("generation") or {}
    if gen.get("skipped"):
        con.print(f"generation  SKIPPED — {gen.get('reason', '')}")
    else:
        mark = "PASS" if gen.get("ok") else "FAIL"
        con.print(
            f"generation  {gen.get('grounded', 0)}/{gen.get('cases', 0)} grounded  "
            f"hallucination={gen.get('hallucination_rate')}  "
            f"model={gen.get('model')} prompt={gen.get('prompt_version')}  {mark}"
        )
        for f in gen.get("failures", []):
            con.print(f"  [red]✗ {f['id']}[/red] {f.get('reason', '')}")
    for key, s in suites.items():
        if not key.startswith("benchmark:"):
            continue
        if s.get("error"):
            con.print(f"[bold]{key}[/bold]  ERROR — {s['error']}")
            continue
        if s.get("ok") is None:
            con.print(f"[bold]{key}[/bold]  PARTIAL — {s.get('skip_reason', '')}")
            continue
        mark = "PASS" if s["ok"] else "FAIL"
        con.print(
            f"[bold]{key}[/bold]  {s['passed']}/{s['cases']}  "
            f"detection={s['detection_rate']} clean_fp={s['clean_fp']}/{s['clean_total']}  {mark}"
        )
        for cat, cal in (s.get("by_category") or {}).items():
            con.print(f"  {cat}: {cal['detected']}/{cal['vuln']} detected clean_fps={cal['fps']}/{cal['clean']}")
        for f in s.get("failures", []):
            con.print(f"  [red]✗ {f['id']}[/red] {f.get('reason', '')}")
        for g in s.get("known_gaps", []):
            con.print(f"  [dim]○ {g['id']} (known gap: {g.get('known_gap', '')})[/dim]")
    con.print("OVERALL " + ("[green]PASS[/green]" if result["ok"] else "[red]FAIL[/red]"))


def run(
    suite: str = "all",
    json_output: bool = False,
    ci: bool = False,
    gen: bool = False,
    file: str | None = None,
    max_mutants: int = 10,
    name: str | None = None,
) -> int:
    """Entry point for `p eval`."""
    from patchi.core.evals.runner import eval_all, eval_gate, eval_generation, eval_noise

    root = require_project_root()
    suite = (suite or "all").lower()
    if suite == "gen":
        result = {
            "suites": {
                "gate": _skipped("gate", "suite not requested"),
                "noise": _skipped("noise", "suite not requested"),
                "generation": eval_generation(root),
            },
            "ok": False,
        }
        result["ok"] = result["suites"]["generation"].get("ok") is True
    elif suite == "gate":
        g = eval_gate(root)
        result = {
            "suites": {
                "gate": g,
                "noise": _skipped("noise", "suite not requested"),
                "generation": _skipped(
                    "generation",
                    "needs a model; run `p eval gen` (spends tokens)",
                ),
            },
            "ok": bool(g["ok"]),
        }
    elif suite == "noise":
        n = eval_noise(root)
        result = {
            "suites": {
                "gate": _skipped("gate", "suite not requested"),
                "noise": n,
                "generation": _skipped(
                    "generation",
                    "needs a model; run `p eval gen` (spends tokens)",
                ),
            },
            "ok": bool(n["ok"]),
        }
    elif suite == "mut":
        from patchi.core.testing.mutation_tester import run_cli as _mut_run

        return _mut_run(
            file=file or "",
            max_mutants=max_mutants,
        )
    elif suite == "benchmark" or suite.startswith("benchmark:"):
        from patchi.core.evals.benchmark import eval_benchmark, list_benchmarks

        picked = suite.split(":", 1)[1] if ":" in suite else (name or "")
        names = [picked] if picked else list_benchmarks()
        if not names:
            result = {
                "suites": {},
                "ok": False,
                "error": "no benchmarks found under evals/benchmarks/",
            }
        else:
            suites = {}
            for bench in names:
                suites[f"benchmark:{bench}"] = eval_benchmark(bench)
            suites["generation"] = _skipped(
                "generation", "needs a model; run `p eval gen` (spends tokens)"
            )
            ok_vals = [s.get("ok") for s in suites.values() if s.get("ok") is not None]
            result = {
                "suites": suites,
                "ok": bool(ok_vals) and all(ok_vals),
            }
    else:
        result = eval_all(root, include_generation=gen)

    if json_output:
        print(json.dumps(result, indent=2, default=str))
    else:
        _render(result)
        # §3.4: hallucination rate is a first-class number — same status as
        # test pass rate. Reported from the harness's live counters (this
        # process) plus any harness history the current run produced.
        try:
            from patchi.core.ai.harness import stats as _ai_stats

            hs = _ai_stats.as_dict()
            if hs["calls"] or hs["grounded"] or hs["hallucinated"]:
                con.print(
                    f"[bold]ai_harness[/bold]  calls={hs['calls']} "
                    f"first_try={hs['validated_first_try']} retried={hs['retried']} "
                    f"escalated={hs['escalated']}"
                )
                if hs["grounded"] or hs["hallucinated"]:
                    con.print(
                        f"  grounded={hs['grounded']} hallucinated={hs['hallucinated']} "
                        f"hallucination_rate={hs['hallucination_rate']}"
                    )
        except Exception:
            pass
    if ci and not result["ok"]:
        return 1
    return 0
