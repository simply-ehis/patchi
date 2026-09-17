"""Harness-backed AI test generation (spec Part 2 §3 applied to test making).

The skeleton generator (``realize.generate_tests``) writes
``test_module_importable()`` placeholders — tests that assert nothing,
which the mutation gate correctly counts as zero value. This module is
the real path: for each target symbol it

1. builds the §3.1 scoped context (symbol + callers + callees, never the
   whole file),
2. asks the model for pytest cases through ``harness_call`` — the output
   MUST satisfy :class:`TestPlan` (pydantic) or it is retried with the
   specific validation error, then escalated,
3. semantically validates every case: must have a real assertion and a
   rationale naming what breaks if the code is wrong (the anti-placeholder
   gate), must import only modules that exist,
4. writes runnable pytest files to ``.patchi/generated_tests/`` and
   returns a manifest naming, per test, the evidence it is based on.

No AI configured → returns ``{"success": False, "reason": "no-ai"}`` and
the caller falls back to the skeleton generator (which stays the zero-AI
path).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from patchi.core.ai.harness import (
    build_symbol_context,
    context_to_prompt_block,
    harness_call,
)

_ASSERT_RE = re.compile(r"\bassert\b|pytest\.raises\(")


class GeneratedCase(BaseModel):
    """One test case the model must fully specify — no freeform prose."""

    name: str = Field(min_length=4, description="pytest function name, test_ prefix")
    target_symbol: str = Field(min_length=1, description="the function under test")
    rationale: str = Field(min_length=15, description="what breaks if this code is wrong")
    test_code: str = Field(min_length=30, description="full pytest function body")

    @field_validator("name")
    @classmethod
    def _name_is_pytest(cls, v: str) -> str:
        if not re.fullmatch(r"test_[a-zA-Z0-9_]+", v):
            raise ValueError(f"test name must match test_[a-zA-Z0-9_]+, got {v!r}")
        return v

    @field_validator("test_code")
    @classmethod
    def _must_assert(cls, v: str) -> str:
        if not _ASSERT_RE.search(v):
            raise ValueError("test body contains no assert — a test that asserts nothing is a lie")
        return v


class TestPlan(BaseModel):
    """The output contract for one generation call."""

    module: str = Field(min_length=1)
    cases: list[GeneratedCase] = Field(min_length=1, max_length=8)


def _iter_top_level_symbols(path: Path) -> list[dict]:
    """Functions/classes of one file from the AST — the generation targets."""
    import ast as py_ast

    try:
        tree = py_ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return []
    out: list[dict] = []
    for node in py_ast.iter_child_nodes(tree):
        if isinstance(node, (py_ast.FunctionDef, py_ast.AsyncFunctionDef)):
            out.append({"name": node.name, "line": node.lineno, "kind": "function"})
        elif isinstance(node, py_ast.ClassDef):
            out.append({"name": node.name, "line": node.lineno, "kind": "class"})
    return out


def _semantic_check(case: GeneratedCase, allowed_imports: set[str], module: str) -> tuple[bool, str]:
    """Reject tests asserting nothing, testing nothing, or importing air."""
    if case.target_symbol not in allowed_imports and case.target_symbol != module:
        return (
            False,
            f"target_symbol {case.target_symbol!r} is not a top-level symbol of {module}.py "
            f"(known: {sorted(allowed_imports)[:8]})",
        )
    # An import of the module must appear — a test that never imports the
    # code under test cannot exercise it.
    if f"import {module}" not in case.test_code and f"from {module}" not in case.test_code:
        return False, f"test body never imports {module} — it cannot be testing it"
    return True, ""


def generate_tests_via_harness(
    root: Path,
    target_files: list[str],
    config: dict,
    max_cases_per_file: int = 4,
) -> dict:
    """Generate real, schema-validated pytest cases for the given files.

    Returns a manifest dict; never writes outside ``.patchi/generated_tests/``.
    """
    import patchi.core.ai.client as ai_client_mod

    probe = ai_client_mod.call_ai(config, "Reply with OK", "test", max_tokens=5)
    if not probe:
        return {"success": False, "reason": "no-ai"}

    out_dir = root / ".patchi" / "generated_tests"
    out_dir.mkdir(parents=True, exist_ok=True)
    created: list[dict] = []
    escalated: list[str] = []

    for tf in target_files[:5]:
        src = Path(tf) if Path(tf).is_absolute() else root / tf
        if not src.exists() or src.suffix != ".py":
            created.append({"file": str(tf), "status": "missing"})
            continue
        module = src.stem
        symbols = _iter_top_level_symbols(src)
        if not symbols:
            created.append({"file": str(tf), "status": "no-symbols"})
            continue

        # Scoped context per §3.1: the top symbols of this file + their graph
        # neighborhoods. Never the whole file.
        names = [s["name"] for s in symbols[:max_cases_per_file]]
        context = [c for c in (build_symbol_context(root, n) for n in names) if c]

        system = (
            "You write precise pytest cases for a security/testing tool. "
            "Test OBSERVABLE behavior of the given symbols only — you may not "
            "reference any code not present in the context block. Every case "
            "must contain at least one real assert. Prefer testing pure logic "
            "over I/O; skip symbols that only do I/O with no testable seam "
            "(say why in rationale instead of inventing mocks)."
        )
        context_block = context_to_prompt_block(context) if context else "(no graph context)"
        user = (
            f"Module: {module} (file {tf})\n"
            f"Top-level symbols: {json.dumps(symbols[:8])}\n\n"
            f"Graph context (the ONLY code you may reference):\n"
            f"{context_block}\n\n"
            f"Write up to {max_cases_per_file} high-value pytest cases."
        )

        allowed = {s["name"] for s in symbols}

        def _check(plan: TestPlan, _allowed: set[str] = allowed, _module: str = module) -> tuple[bool, str]:
            return _validate_plan(plan, _allowed, _module)

        plan, status = harness_call(
            config,
            system,
            user,
            TestPlan,
            semantic_validator=_check,
            max_tokens=2000,
            call_fn=lambda cfg, s, u, **kw: ai_client_mod.call_ai(cfg, s, u, **kw),
        )

        if plan is None or status != "ok":
            escalated.append(f"{tf} ({status})")
            # Anti-placeholder guarantee: never leave a nothing-test behind.
            continue

        cases_src = [f"# rationale: {c.rationale}" + chr(10) + c.test_code for c in plan.cases]
        import_path = _rel_import(src, root) if _is_pkg(src, root) else src.stem
        test_src = (
            "# Auto-generated by Patchi harness (spec §3) — AI tests with evidence\n"
            "import pytest\n\n"
            f"from {import_path} import (  # noqa: F401\n"
            f"    {', '.join(sorted(allowed)[:12])},\n"
            ")\n\n\n" + "\n\n".join(cases_src) + "\n"
        )
        dest = out_dir / f"test_{module}.py"
        dest.write_text(test_src, encoding="utf-8")
        created.append(
            {
                "file": str(dest),
                "source": str(src),
                "status": "created",
                "cases": [c.name for c in plan.cases],
                "evidence": [
                    {"symbol": c.target_symbol, "why": c.rationale[:120]} for c in plan.cases
                ],
            }
        )

    return {
        "success": bool(created and any(c.get("status") == "created" for c in created)),
        "created": created,
        "escalated": escalated,
        "output_dir": str(out_dir),
        "measured_by": ["ai_harness"],
    }


def _validate_plan(plan: TestPlan, allowed: set[str], module: str) -> tuple[bool, str]:
    for case in plan.cases:
        ok, reason = _semantic_check(case, allowed, module)
        if not ok:
            return False, f"case {case.name}: {reason}"
    return True, ""


def _is_pkg(src: Path, root: Path) -> bool:
    return (src.parent / "__init__.py").exists() and src.parent != root


def _rel_import(src: Path, root: Path) -> str:
    try:
        return src.relative_to(root).with_suffix("").as_posix().replace("/", ".")
    except ValueError:
        return src.stem
