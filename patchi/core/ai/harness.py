"""AI Harness — scoped context, structured output, reject-and-retry (spec §3).

Every AI-assisted step in the pipeline (fix candidate generation, test
generation, semantic classification) goes through THIS module, never a bare
``call_ai`` with a whole-file dump and a regex on the other end.

The three contract pieces (spec §3.1–3.3):

1.  **Scoped context, not raw file dumps.** ``build_symbol_context`` takes a
    target symbol and returns the symbol's signature/doc plus its direct
    graph neighborhood (callers + callees) from the SymbolGraph — never
    whole-file or whole-repo context. The same scoped-context pattern is
    what took the seeded generation eval from 9 hallucinated failures on a
    raw whole-file prompt to 1 with a graph-scoped harness (Testing
    Strategy §4) — same model, only the harness changed.

2.  **Structured output contract, enforced.** ``harness_call`` takes a
    pydantic model, asks the model for JSON matching that model, parses and
    VALIDATES immediately, and never returns freeform text to regex
    downstream.

3.  **Reject-and-retry, not accept-and-hope.** On schema failure (or an
    explicit semantic validator), the specific validation error is fed back
    into the prompt for exactly one retry. A result that fails again (or a
    model that never answers) is escalated to ``review`` — never silently
    accepted as ``ok``.

Measurability (spec §3.4): every call's outcome lands in
``patchi.core.ai.harness_stats`` — validated / retried / escalated counts
and, when the harness scope was used for generation, the grounded-vs-
hallucinated split the eval runner already tracks. `p eval` reports it as a
first-class number next to test pass rate.

The harness is deliberately dependency-minimal (pydantic is already a
transitive dep) and reuses ``call_ai``'s provider rotation, offline gate and
timeouts. It only ADDS the contract.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from loguru import logger
from pydantic import BaseModel

from patchi.core.ai.client import call_ai

_log = logging.getLogger("patchi.ai.harness")

# Every harness output contract is a pydantic model — the TypeVar is bounded
# so `schema.model_validate(...)` type-checks (spec §3.2).
T = TypeVar("T", bound=BaseModel)

MAX_RETRIES = 1  # spec §3.3: reject → retry ONCE with the failure fed back → escalate

# ── Stats (§3.4: first-class numbers, not vibes) ─────────────────────────────


class HarnessStats:
    """In-process counters for AI-call outcomes."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.calls = 0
        self.validated_first_try = 0
        self.retried = 0
        self.escalated = 0
        self.unavailable = 0
        self.grounded = 0
        self.hallucinated = 0

    def as_dict(self) -> dict:
        measured = self.grounded + self.hallucinated
        return {
            "calls": self.calls,
            "validated_first_try": self.validated_first_try,
            "retried": self.retried,
            "escalated": self.escalated,
            "unavailable": self.unavailable,
            "grounded": self.grounded,
            "hallucinated": self.hallucinated,
            "hallucination_rate": (round(self.hallucinated / measured, 3) if measured else None),
        }


stats = HarnessStats()

# ── 1. Scoped context builder (SymbolGraph neighborhood) ────────────────────


def build_symbol_context(
    root: Path,
    symbol_name: str,
    radius: int = 1,
    max_neighbors: int = 12,
) -> dict | None:
    """Build the §3.1 scoped context for ONE target symbol.

    Returns {name, kind, file, line, params, docstring, callers, callees}
    built from the SymbolGraph — the target symbol + its direct graph
    neighborhood, nothing else. Whole files are NEVER included. Returns None
    when the graph cannot answer for this symbol (callers decide fallback).
    """
    try:
        from patchi.core.brain.symbol_graph import SymbolGraph

        with SymbolGraph(root) as sym_graph:
            sym_graph.ensure_built()
            sym = sym_graph.get_symbol(symbol_name)
            if not sym:
                return None
            entry: dict = {
                "name": sym.name,
                "kind": sym.kind,
                "file": sym.file,
                "line": sym.line,
                "is_exported": sym.is_exported,
                "params": sym.params,
                "docstring": (sym.docstring or "")[:200],
                "callers": [],
                "callees": [],
            }
            if radius >= 1:
                for dep in sym_graph.get_dependents(sym.name, sym.file)[:max_neighbors]:
                    entry["callers"].append({"name": dep.name, "file": dep.file, "kind": dep.kind})
                for dep in sym_graph.get_dependencies(sym.id)[:max_neighbors]:
                    entry["callees"].append({"name": dep.name, "file": dep.file, "kind": dep.kind})
            return entry
    except Exception as e:
        logger.debug(f"build_symbol_context failed for {symbol_name}: {e}")
        return None


def build_neighborhood_context(root: Path, symbol_names: list[str], radius: int = 1) -> list[dict]:
    """Scoped context for MANY symbols (graph-scoped test/fix phases)."""
    out: list[dict] = []
    for name in symbol_names:
        ctx = build_symbol_context(root, name, radius=radius)
        if ctx is not None:
            out.append(ctx)
    return out


def context_to_prompt_block(context: dict | list[dict]) -> str:
    """Render scoped context as a compact, token-bounded prompt block."""
    entries = context if isinstance(context, list) else [context]
    blocks: list[str] = []
    for c in entries:
        if not isinstance(c, dict):
            continue
        lines = [f"- {c.get('kind', 'symbol')} {c.get('name', '?')} ({c.get('file', '?')}:{c.get('line', '?')})"]
        params = c.get("params")
        if params:
            lines.append(f"  params: {json.dumps(params)[:200]}")
        if c.get("docstring"):
            lines.append(f"  doc: {str(c['docstring'])[:150]}")
        callers = c.get("callers") or []
        if callers:
            lines.append("  callers: " + ", ".join(str(x.get("name", "?")) for x in callers[:6]))
        callees = c.get("callees") or []
        if callees:
            lines.append("  callees: " + ", ".join(str(x.get("name", "?")) for x in callees[:6]))
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


# ── 2+3. Structured call with enforced schema + reject-and-retry ────────────


def _json_fence_parse(raw: str):
    """Parse a JSON object out of a possibly-fenced model response."""
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        pass
    m = re.search(r"```(?:json)?\s*\n(.*?)```", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except (ValueError, TypeError):
            return None
    m = re.search(r"(\{.*\}|\[.*\])", raw, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except (ValueError, TypeError):
            return None
    return None


def harness_call(
    config: dict,
    system_prompt: str,
    user_prompt: str,
    schema: type[T],
    semantic_validator=None,
    max_tokens: int = 2000,
    timeout: float | None = None,
    call_fn: Callable[..., str | None] | None = None,
) -> tuple[T | None, str]:
    """Make an AI call whose output MUST satisfy ``schema`` (pydantic model).

    Returns ``(result, status)`` where status is one of:
      - "ok"        — validated (first try or after one retry)
      - "escalate"  — model output never satisfied the schema → human review
      - "review"    — schema passed but the semantic validator rejected it
      - "unavailable" — no model / offline / call error

    The result is the validated pydantic instance — never freeform text.

    ``call_fn`` lets the caller inject the low-level transport (signature:
    ``(config, system_prompt, user_prompt, max_tokens=..., timeout=...) -> str | None``).
    Defaults to this module's ``call_ai``. Passing a late-bound resolver (e.g.
    ``lambda *a, **kw: module.call_ai(*a, **kw)``) keeps ``unittest.mock.patch``
    on the caller's own module working — the mock is resolved at call time,
    not captured at import time.

    Contract (spec §3.2–3.3): parse + validate IMMEDIATELY; on failure retry
    ONCE with the specific validation errors fed back into the prompt; a
    second failure escalates to human review. A malformed result is never
    silently accepted.
    """
    stats.calls += 1

    schema_json = _schema_to_json(schema)
    contract_system = (
        f"{system_prompt}\n\n"
        "OUTPUT CONTRACT: Reply with a single JSON object and nothing else — "
        "no prose, no code fences, no markdown. It must validate against this "
        f"schema:\n{schema_json}"
    )

    parsed = None
    validation_error = ""
    raw = ""

    for attempt in (0, MAX_RETRIES):
        attempt_prompt = user_prompt
        if attempt > 0 and validation_error:
            # §3.3: feed the SPECIFIC failure back into the prompt.
            attempt_prompt = (
                f"{user_prompt}\n\n"
                f"Your previous reply was REJECTED. It failed validation with:\n"
                f"{validation_error}\n"
                f"Return ONLY a corrected JSON object matching the schema."
            )
            stats.retried += 1

        _caller = call_fn or call_ai
        _out = _caller(config, contract_system, attempt_prompt, max_tokens=max_tokens, timeout=timeout)
        raw = _out or ""
        if not raw:
            if attempt == MAX_RETRIES:
                stats.unavailable += 1
                return None, "unavailable"
            continue

        parsed = _json_fence_parse(raw)
        if parsed is None:
            validation_error = "response was not parseable as JSON"
            continue

        try:
            validated = schema.model_validate(parsed)
        except Exception as e:  # pydantic.ValidationError
            validation_error = str(e)[:800]
            continue

        if semantic_validator is not None:
            try:
                sem_ok, sem_reason = semantic_validator(validated)
            except Exception as e:
                sem_ok, sem_reason = False, f"semantic validator raised: {e}"
            if not sem_ok:
                validation_error = f"semantic check failed: {sem_reason}"
                continue

        if attempt == 0:
            stats.validated_first_try += 1
        return validated, "ok"

    # Never accept-and-hope: escalate with the last failure attached.
    stats.escalated += 1
    return None, "escalate"


def _schema_to_json(schema: type[BaseModel]) -> str:
    try:
        return json.dumps(schema.model_json_schema())[:1500]
    except Exception:
        return str(schema)


# ── Generation grounding checks (§3.4 measurability) ────────────────────────


def check_generation_grounding(
    code: str, must_reference: list[str], root: Path | None = None, language: str = "python"
) -> tuple[bool, str]:
    """Determinism check for generated code (spec §3.3).

    Grounded = references the seeded target symbols AND (for Python)
    compiles. Returns (grounded, reason). Updates the shared stats so the
    harness's hallucination number is measured, not assumed.
    """
    missing = [ref for ref in must_reference if ref and ref not in code]
    if missing:
        stats.hallucinated += 1
        return False, f"missing references: {missing}"

    if language == "python":
        stripped = re.sub(r"```(?:python)?\n(.*?)```", r"\1", code, flags=re.DOTALL)
        try:
            compile(stripped, "<harness-gen>", "exec")
        except SyntaxError as e:
            stats.hallucinated += 1
            return False, f"invalid python: {e}"

    stats.grounded += 1
    return True, "references target + valid syntax"


def record_grounding(generated: list[dict]) -> dict:
    """Record a batch of generation outcomes into the stats + return them.

    Each entry: {"grounded": bool, ...}. TEST_GENERATION evidence attaches
    the returned summary so "hallucination rate not measured" partials
    disappear whenever the harness actually ran.
    """
    for g in generated:
        if g.get("grounded"):
            stats.grounded += 1
        else:
            stats.hallucinated += 1
    return stats.as_dict()
