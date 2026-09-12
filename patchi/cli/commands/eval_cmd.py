"""
Eval command — score the pipeline against the standing eval set (spec §5).

Usage:
    p eval              → all offline suites (gate + noise)
    p eval gate         → ConfidenceGate routing cases only
    p eval noise        → NoiseFilter cases only
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
        s = suites[name]
        if s.get("skipped"):
            con.print(f"[bold]{name}[/bold]  SKIPPED")
            continue
        mark = "PASS" if s["ok"] else "FAIL"
        con.print(f"[bold]{name}[/bold]  {s['passed']}/{s['cases']}  {mark}")
        for f in s.get("failures", []):
            con.print(
                f"  [red]✗ {f['id']}[/red] expected={f['expected']} actual={f['actual']}"
            )
    gate = suites["gate"]
    if not gate.get("skipped"):
        con.print(
            f"vuln recall={gate['vuln_recall']}  "
            f"clean defend escapes={gate['clean_defend_escapes']}"
        )
    gen = suites["generation"]
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
    con.print("OVERALL " + ("[green]PASS[/green]" if result["ok"] else "[red]FAIL[/red]"))


def run(
    suite: str = "all",
    json_output: bool = False,
    ci: bool = False,
    gen: bool = False,
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
                    "hallucination rate needs a model + prompt version; not run offline",
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
                    "hallucination rate needs a model + prompt version; not run offline",
                ),
            },
            "ok": bool(n["ok"]),
        }
    else:
        result = eval_all(root, include_generation=gen)

    if json_output:
        print(json.dumps(result, indent=2, default=str))
    else:
        _render(result)
    if ci and not result["ok"]:
        return 1
    return 0
