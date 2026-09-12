"""Eval runner — scores ConfidenceGate + NoiseFilter against labeled cases.

Deterministic and fully offline: no model calls, no browsers, no network.
`p eval` is the regression gate for every change to scanning/scoring.
"""

from __future__ import annotations

import json
from pathlib import Path

_EVALS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "evals" / "cases"


def _load_cases(name: str) -> list[dict]:
    with open(_EVALS_DIR / name, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(f"{name}: top level must be a list of cases")
    return data


def eval_gate(root: Path, config: dict | None = None) -> dict:
    """Run gate_cases.json through ConfidenceGate in an isolated tmp root.

    A fresh tmp root (not the project root) keeps `seed_known_fp` cases from
    polluting the project's real FP memory.
    """
    import tempfile

    from patchi.core.agents.base import Finding, Severity
    from patchi.core.security.confidence_gate import ConfidenceGate
    from patchi.core.security.orchestrator import CorrelatedFinding

    cases = _load_cases("gate_cases.json")
    work = Path(tempfile.mkdtemp(prefix="patchi-eval-gate-"))
    (work / ".patchi").mkdir(exist_ok=True)
    base_gate = ConfidenceGate(work, config or {})

    details: list[dict] = []
    for case in cases:
        # Per-case gate config (tests a knob, not the default behavior).
        # Shares the tmp root so FP-memory seeding still works.
        if case.get("gate_config"):
            merged = dict(config or {})
            merged_cfg = dict(merged.get("confidence_gate", {}))
            merged_cfg.update(case["gate_config"])
            merged["confidence_gate"] = merged_cfg
            gate = ConfidenceGate(work, merged)
        else:
            gate = base_gate
        fd = case["finding"]
        finding = Finding(
            agent=fd.get("agent", "eval"),
            type=fd.get("type", ""),
            severity=Severity(fd.get("severity", "medium")),
            file=fd.get("file", ""),
            line=fd.get("line", 0),
            message=fd.get("message", ""),
            code_snippet=fd.get("code_snippet", ""),
            cwe=fd.get("cwe", ""),
        )
        if case.get("noise_category"):
            finding.noise_category = case["noise_category"]  # type: ignore[attr-defined]
        if case.get("seed_known_fp"):
            gate.record_false_positives(
                [{"file": finding.file, "type": finding.type, "line": finding.line}]
            )
        cf = CorrelatedFinding(
            finding=finding,
            confirmed_by=list(fd.get("confirmed_by", [])),
            composite_score=float(fd.get("composite_score", 0.0)),
        )
        gated = gate.gate(cf, ai_confidence=case.get("ai_confidence"))
        details.append(
            {
                "id": case["id"],
                "kind": case.get("kind"),
                "expected": case["expect_routing"],
                "actual": gated.routing,
                "score": round(gated.confidence_score, 3),
                "tier": gated.confidence_tier,
                "pass": gated.routing == case["expect_routing"],
            }
        )

    total = len(details)
    passed = sum(1 for d in details if d["pass"])
    vuln = [d for d in details if d["kind"] == "vuln"]
    clean = [d for d in details if d["kind"] == "clean"]
    vuln_recall = (
        sum(1 for d in vuln if d["actual"] != "discard") / len(vuln) if vuln else 1.0
    )
    clean_escapes = sum(1 for d in clean if d["actual"] == "defend")
    # §4 calibration: per-tier precision of "tier means real" (vuln fraction)
    # and routing distribution — thresholds are validated against THESE
    # numbers, not trusted as defaults.
    tier_calibration: dict[str, dict] = {}
    for tier in ("high", "medium", "low"):
        in_tier = [d for d in details if d["tier"] == tier]
        if not in_tier:
            continue
        tier_calibration[tier] = {
            "n": len(in_tier),
            "vuln_fraction": round(
                sum(1 for d in in_tier if d["kind"] == "vuln") / len(in_tier), 3
            ),
            "routing": {
                r: sum(1 for d in in_tier if d["actual"] == r)
                for r in ("defend", "ai_analyze", "human_review", "discard")
            },
        }
    return {
        "suite": "gate",
        "cases": total,
        "passed": passed,
        "routing_accuracy": round(passed / total, 3) if total else 1.0,
        "vuln_recall": round(vuln_recall, 3),
        "clean_defend_escapes": clean_escapes,
        "tier_calibration": tier_calibration,
        "thresholds": {
            "high": 0.7,
            "medium": 0.4,
            "fp_penalty": gate.fp_penalty,
            "ai_weight": gate.ai_weight,
            "min_agents_for_defend": gate.min_agents_for_defend,
            "min_agents_to_keep": gate.min_agents_to_keep,
        },
        "ok": passed == total and clean_escapes == 0,
        "failures": [d for d in details if not d["pass"]],
        "details": details,
    }


def eval_noise(root: Path, config: dict | None = None) -> dict:
    """Run noise_cases.json through NoiseFilter (both modes covered by cases)."""
    from patchi.core.security.noise_filter import NoiseFilter

    cases = _load_cases("noise_cases.json")
    details: list[dict] = []
    for case in cases:
        nf_cfg = {"mode": case["mode"]}
        nf_cfg.update(case.get("filter_config", {}))
        nf = NoiseFilter(root, {"noise_filter": nf_cfg})
        kept, _report = nf.apply([{"file": case["file"]}])
        if not kept:
            actual = "discarded"
        elif isinstance(kept[0], dict) and kept[0].get("noise_category"):
            actual = "capped"
        else:
            actual = "kept"
        details.append(
            {
                "id": case["id"],
                "file": case["file"],
                "mode": case["mode"],
                "expected": case["expect"],
                "actual": actual,
                "pass": actual == case["expect"],
            }
        )

    total = len(details)
    passed = sum(1 for d in details if d["pass"])
    return {
        "suite": "noise",
        "cases": total,
        "passed": passed,
        "accuracy": round(passed / total, 3) if total else 1.0,
        "ok": passed == total,
        "failures": [d for d in details if not d["pass"]],
        "details": details,
    }


GEN_PROMPT_VERSION = "gen-v1"
GEN_SYSTEM = (
    "You write a minimal Python regression test for the function below. "
    "Reply with ONLY a python code block, no prose. "
    f"Prompt version: {GEN_PROMPT_VERSION}."
)


def _model_available(config: dict | None) -> tuple[bool, str]:
    """5-token probe (same check `p test generate` uses). No spend if dead."""
    try:
        from patchi.core.ai.client import call_ai

        probe = call_ai(config or {}, "Reply with OK", "test", max_tokens=5)
        if probe:
            return True, "model answered probe"
        return False, "model probe returned empty (no key / offline)"
    except Exception as e:
        return False, f"model probe failed: {e}"


def _model_id(config: dict | None) -> str:
    try:
        ai = (config or {}).get("ai", {})
        keys = ai.get("keys", []) or []
        if keys:
            k = keys[0]
            return f"{k.get('nickname', '?')}/{k.get('model', '?')}"
        return "unconfigured"
    except Exception:
        return "unknown"


def eval_generation(
    root: Path, config: dict | None = None, max_tokens: int = 300
) -> dict:
    """Model-backed generation eval (§5/§2 TEST_GENERATION Done column).

    For each seeded case: ask the model for a regression test, then score
    GROUNDED (references the seeded symbol AND is valid Python) vs
    HALLUCINATED. hallucination_rate = 1 - grounded/total, recorded per
    model + prompt version. No model → SKIPPED with reason, never a number.
    """
    from patchi.core import config as _cfg

    cfg = config
    if cfg is None:
        try:
            cfg = _cfg.load(root)
        except Exception:
            cfg = {}
    model = _model_id(cfg)
    ok, why = _model_available(cfg)
    if not ok:
        return {
            "suite": "generation",
            "ok": None,
            "skipped": True,
            "reason": why,
            "model": model,
            "prompt_version": GEN_PROMPT_VERSION,
        }

    from patchi.core.ai.client import call_ai

    cases = _load_cases("generation_cases.json")
    details: list[dict] = []
    for case in cases:
        prompt = (
            f"Target file: {case['target_file']}\n"
            f"Target function: {case['target_symbol']}\n"
            f"Code:\n{case['seed']}\n"
        )
        try:
            resp = call_ai(cfg, GEN_SYSTEM, prompt, max_tokens=max_tokens) or ""
        except Exception as e:
            resp = ""
            details.append(
                {
                    "id": case["id"],
                    "grounded": False,
                    "reason": f"model call failed: {e}",
                    "response_chars": 0,
                }
            )
            continue
        refs = [s for s in case.get("must_reference", []) if s in resp]
        try:
            compile(resp, "<gen>", "exec")
            valid_py = True
        except SyntaxError:
            # Model may wrap in fences — try extracting the block once
            import re

            m = re.search(r"```(?:python)?\n(.*?)```", resp, re.DOTALL)
            try:
                compile(m.group(1) if m else "", "<gen>", "exec")
                valid_py = bool(m)
            except SyntaxError:
                valid_py = False
        grounded = bool(refs) and valid_py
        details.append(
            {
                "id": case["id"],
                "grounded": grounded,
                "reason": (
                    "references target + valid python"
                    if grounded
                    else f"missing refs={refs} valid_py={valid_py}"
                ),
                "response_chars": len(resp),
            }
        )

    total = len(details)
    grounded_n = sum(1 for d in details if d["grounded"])
    rate = round(1.0 - grounded_n / total, 3) if total else 1.0
    return {
        "suite": "generation",
        "cases": total,
        "grounded": grounded_n,
        "hallucination_rate": rate,
        "model": model,
        "prompt_version": GEN_PROMPT_VERSION,
        "ok": rate == 0.0,
        "failures": [d for d in details if not d["grounded"]],
        "details": details,
    }


def eval_all(
    root: Path, config: dict | None = None, include_generation: bool = False
) -> dict:
    """Run offline suites; generation only with include_generation=True.

    Generation spends model tokens, so `p eval` stays offline by default and
    `p eval --gen` opts in. Either way the report states what ran.
    """
    gate = eval_gate(root, config)
    noise = eval_noise(root, config)
    if include_generation:
        generation = eval_generation(root, config)
        ok = bool(gate["ok"] and noise["ok"] and generation.get("ok"))
    else:
        generation = {
            "suite": "generation",
            "ok": None,
            "skipped": True,
            "reason": "opt in with `p eval --gen` (spends model tokens)",
        }
        ok = bool(gate["ok"] and noise["ok"])
    return {
        "suites": {"gate": gate, "noise": noise, "generation": generation},
        "ok": ok,
    }
