"""
Project Charter — the Guard Rails pillar of the Patchi super-agent.

The user declares what the project *should be* in natural language:

    p charter "This is a Flask+React monorepo. Frontend must never import
    backend DB modules. All API routes need tests. No hardcoded secrets.
    Services under 80 lines."

This is parsed (heuristically now, LLM-assisted later) into a structured
:class:`Charter` with four rule families:

    - stack       → expected languages / frameworks (drift if a new one appears)
    - boundaries   → forbidden import edges between layers (architecture drift)
    - conventions  → naming, max file/function size, required test coverage
    - security     → no hardcoded secrets, no pickle/eval, parameterized queries

The charter is stored in `.patchi/memory/charter.json` and checked on every
scan.  Violations are surfaced as ``charter-drift`` findings so that **both
humans (via ``p scan``) and agents (via the Governor) stay in context**.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# ── Known frameworks / languages for stack detection ──────────────────────────

_KNOWN_FRAMEWORKS = [
    "flask", "django", "fastapi", "starlette", "tornado", "sanic", "litestar",
    "express", "fastify", "koa", "nestjs", "next.js", "nuxt", "sveltekit",
    "remix", "astro", "react", "vue", "angular", "svelte", "solid.js", "qwik",
    "spring", "quarkus", "micronaut", "laravel", "symfony", "rails", "sinatra",
    "gin", "echo", "fiber", "chi", "actix", "axum", "rocket", "tauri", "warp",
    "hono", "trpc", "vapor", "phoenix",
]

_KNOWN_LANGUAGES = [
    "python", "javascript", "typescript", "go", "golang", "rust", "java",
    "php", "ruby", "swift", "kotlin", "scala", "c#", "csharp", "c++", "dart",
]

# Role words → subsystem layer names they map to
_ROLE_MAP: dict[str, set[str]] = {
    "frontend": {"ui"},
    "ui": {"ui"},
    "client": {"ui"},
    "backend": {"api", "data", "core", "agents"},
    "server": {"api", "core"},
    "database": {"data"},
    "db": {"data"},
    "auth": {"auth"},
    "api": {"api"},
    "data": {"data"},
    "core": {"core"},
}


# ── Dataclasses ────────────────────────────────────────────────────────────────


import logging

_log = logging.getLogger("patchi.brain.charter")

@dataclass
class Charter:
    """Structured project guard rails parsed from natural language."""

    raw_text: str = ""
    stack: dict = field(default_factory=lambda: {"languages": [], "frameworks": []})
    boundaries: list[dict] = field(default_factory=list)  # [{"from": str, "to": str}]
    conventions: dict = field(default_factory=dict)  # max_file_lines, require_tests_for_routes, ...
    security: list[str] = field(default_factory=list)  # rule names
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "raw_text": self.raw_text,
            "stack": self.stack,
            "boundaries": self.boundaries,
            "conventions": self.conventions,
            "security": self.security,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Charter":
        return cls(
            raw_text=d.get("raw_text", ""),
            stack=d.get("stack", {"languages": [], "frameworks": []}),
            boundaries=d.get("boundaries", []),
            conventions=d.get("conventions", {}),
            security=d.get("security", []),
            notes=d.get("notes", []),
        )


@dataclass
class CharterViolation:
    """A single guard-rail breach detected during a scan."""

    rule: str  # which charter rule was broken
    severity: str  # "high" | "medium" | "low"
    message: str
    file: str = ""  # offending file (if known)
    layer: str = ""  # offending layer (if known)

    def to_finding(self) -> dict:
        return {
            "agent": "CharterGuard",
            "type": "charter-drift",
            "severity": self.severity,
            "file": self.file,
            "message": self.message,
            "rule": self.rule,
            "layer": self.layer,
        }


# ── Parsing ───────────────────────────────────────────────────────────────────


def parse_charter(text: str, config: dict | None = None) -> Charter:
    """Parse a natural-language charter into a structured :class:`Charter`.

    Uses deterministic heuristics (always available, free).  If an LLM is
    configured, :func:`parse_charter_with_ai` can be used instead for richer
    extraction; this function is the offline-safe default.
    """
    text_l = text.lower()
    charter = Charter(raw_text=text)

    # ── Stack: frameworks + languages ────────────────────────────────────────
    for fw in _KNOWN_FRAMEWORKS:
        if re.search(rf"\b{re.escape(fw)}\b", text_l):
            if fw not in charter.stack["frameworks"]:
                charter.stack["frameworks"].append(fw)
    for lang in _KNOWN_LANGUAGES:
        if re.search(rf"\b{re.escape(lang)}\b", text_l):
            norm = "golang" if lang == "go" else ("csharp" if lang in ("c#",) else lang)
            if norm not in charter.stack["languages"]:
                charter.stack["languages"].append(norm)

    # ── Boundaries: "X must not import Y" ──────────────────────────────────────
    boundary_patterns = [
        r"([\w./]+)\s*must\s+(?:never|not)\s+import\s+([\w./]+)",
        r"no\s+([\w./]+)\s+importing\s+([\w./]+)",
        r"([\w./]+)\s+should\s+(?:never|not)\s+import\s+([\w./]+)",
    ]
    for pat in boundary_patterns:
        for m in re.finditer(pat, text_l):
            groups = m.groups()
            if len(groups) == 1:
                # "no X importing Y" form
                src, tgt = _split_role_phrase(groups[0])
            else:
                src, tgt = groups[0], groups[1]
            charter.boundaries.append({"from": src.strip(), "to": tgt.strip()})

    # ── Conventions: sizes + test coverage ─────────────────────────────────────
    m_lines = re.search(
        r"(?:file|files|service|services|function|functions|module|modules)"
        r"\s+(?:under|below|<\s*|less than)\s*(\d+)\s*lines",
        text_l,
    )
    if m_lines:
        charter.conventions["max_file_lines"] = int(m_lines.group(1))

    if re.search(r"all\s+(?:api\s+)?routes?\s+(?:need|must have|require)\s+tests", text_l):
        charter.conventions["require_tests_for_routes"] = True
    if re.search(r"(?:every|all)\s+(?:function|module|service)\s+(?:needs|must have|requires)\s+tests", text_l):
        charter.conventions["require_tests_for_routes"] = True

    # ── Security rules ─────────────────────────────────────────────────────────
    if re.search(r"no\s+(?:hardcoded?\s+)?secrets?", text_l):
        charter.security.append("no_hardcoded_secrets")
    if re.search(r"\bno\s+pickle\b", text_l):
        charter.security.append("no_pickle")
    if re.search(r"\bno\s+eval\b", text_l):
        charter.security.append("no_eval")
    if re.search(r"parameteri[sz]ed\s+queries", text_l):
        charter.security.append("parameterized_queries")

    return charter


def _split_role_phrase(phrase: str) -> tuple[str, str]:
    """Split a 'X importing Y' phrase into (from, to) role tokens."""
    m = re.search(r"([\w./]+)\s+importing\s+([\w./]+)", phrase)
    if m:
        return m.group(1), m.group(2)
    return phrase, ""


def parse_charter_with_ai(text: str, config: dict) -> "Charter | None":
    """Optional LLM-backed parser. Returns None if AI unavailable or it fails."""
    ai_config = config.get("ai", {})
    has_ai = bool(ai_config.get("keys") or ai_config.get("local_model_name"))
    if not has_ai:
        return None
    try:
        from patchi.core.ai.client import call_ai
    except Exception as e:
        _log.warning("parse_charter_with_ai failed: %s", e)
        return None

    prompt = (
        "Convert the following project charter into JSON with keys: "
        "frameworks (list), languages (list), boundaries (list of {from,to}), "
        "conventions (dict), security (list of rule strings). "
        "Return ONLY JSON.\n\n" + text
    )
    try:
        resp = call_ai(config, "You are a config parser. Output only JSON.", prompt, max_tokens=1024)
    except Exception as e:
        _log.warning("parse_charter_with_ai failed: %s", e)
        return None
    if not resp:
        return None
    # strip fences
    resp = resp.strip()
    if resp.startswith("```"):
        resp = resp.split("```")[1]
        if resp.startswith("json"):
            resp = resp[4:]
    try:
        data = json.loads(resp)
    except (json.JSONDecodeError, ValueError):
        return None

    charter = Charter(raw_text=text)
    charter.stack = data.get("stack", {"languages": [], "frameworks": []})
    charter.boundaries = data.get("boundaries", [])
    charter.conventions = data.get("conventions", {})
    charter.security = data.get("security", [])
    return charter


# ── Resolution helpers ────────────────────────────────────────────────────────


def _resolve_role(token: str) -> set[str]:
    """Map a role/framework/layer token to the subsystem layer names it covers."""
    token_l = token.lower().strip()
    if token_l in _ROLE_MAP:
        return _ROLE_MAP[token_l]
    # Direct subsystem name match
    if token_l in {"auth", "api", "data", "ui", "core", "agents", "tests", "infra"}:
        return {token_l}
    # Framework → its typical subsystem
    fw_to_sub = {
        "react": "ui", "vue": "ui", "angular": "ui", "svelte": "ui",
        "next.js": "ui", "nuxt": "ui", "sveltekit": "ui",
        "flask": "api", "django": "api", "fastapi": "api", "express": "api",
        "spring": "api", "laravel": "api", "rails": "api",
    }
    if token_l in fw_to_sub:
        return {fw_to_sub[token_l]}
    return set()


def _matches_boundary(edge_from: str, edge_to: str, boundary: dict) -> bool:
    """Does a layer dependency edge violate a forbidden boundary?"""
    from_set = _resolve_role(boundary.get("from", ""))
    to_set = _resolve_role(boundary.get("to", ""))
    if not from_set or not to_set:
        return False
    # Direct name match OR role-resolved match
    direct = boundary.get("from", "").lower().strip() in edge_from.lower() and \
        boundary.get("to", "").lower().strip() in edge_to.lower()
    role = (bool(from_set & {edge_from} or any(f in edge_from.lower() for f in from_set))) and \
        (bool(to_set & {edge_to} or any(t in edge_to.lower() for t in to_set)))
    return direct or role


# ── Checking ──────────────────────────────────────────────────────────────────


def check_charter(
    charter: "Charter",
    layers: dict,
    detected_frameworks: list[str] | None = None,
    routes: list | None = None,
    file_infos: list | None = None,
) -> list["CharterViolation"]:
    """Evaluate a charter against the current codebase state.

    Returns a list of :class:`CharterViolation` (empty if fully compliant).
    """
    violations: list[CharterViolation] = []
    if not charter or not layers:
        return violations

    # ── Boundary checks (subsystem-level dependency edges) ─────────────────────
    subsystem_layers = {n: l for n, l in layers.items() if l.get("level") == 2}
    for name, layer in subsystem_layers.items():
        for dep in layer.get("depends_on", []):
            for b in charter.boundaries:
                if _matches_boundary(name, dep, b):
                    violations.append(
                        CharterViolation(
                            rule=f"boundary:{b.get('from')}→{b.get('to')}",
                            severity="high",
                            message=(
                                f"Architecture drift: subsystem '{name}' imports "
                                f"'{dep}', which violates the charter rule "
                                f"'{b.get('from')} must not import {b.get('to')}'."
                            ),
                            layer=name,
                        )
                    )

    # ── Stack drift ───────────────────────────────────────────────────────────
    if detected_frameworks and charter.stack.get("frameworks"):
        expected = {f.lower() for f in charter.stack["frameworks"]}
        actual = {f.lower() for f in detected_frameworks}
        unexpected = actual - expected
        # Only flag clearly-new frameworks, not the same framework under another name
        if unexpected:
            violations.append(
                CharterViolation(
                    rule="stack-drift",
                    severity="medium",
                    message=(
                        f"Stack drift: project uses frameworks not declared in the "
                        f"charter: {', '.join(sorted(unexpected))}. Charter expected: "
                        f"{', '.join(sorted(expected))}."
                    ),
                )
            )

    # ── Convention: require tests for routes ───────────────────────────────────
    if charter.conventions.get("require_tests_for_routes") and routes:
        route_files = {
            r.get("file", "") if isinstance(r, dict) else getattr(r, "file", "")
            for r in routes
        }
        test_files = {
            fi.path
            for fi in (file_infos or [])
            if fi.path
            and (
                "test" in fi.path.lower()
                or fi.path.endswith("_test.py")
                or fi.path.endswith(".test.js")
                or fi.path.endswith(".test.ts")
            )
        }
        untested = [rf for rf in route_files if rf and rf not in test_files]
        if untested:
            violations.append(
                CharterViolation(
                    rule="require_tests_for_routes",
                    severity="low",
                    message=(
                        f"Convention drift: {len(untested)} route file(s) have no "
                        f"test coverage (charter requires tests for all API routes)."
                    ),
                )
            )

    return violations


# ── Persistence helpers ───────────────────────────────────────────────────────


def save_charter(charter: "Charter", root: Path) -> None:
    from patchi.core import memory as mem

    mem.save_charter(charter.to_dict(), root)


def load_charter(root: Path) -> "Charter | None":
    from patchi.core import memory as mem

    data = mem.get_charter(root)
    if not data:
        return None
    return Charter.from_dict(data)
