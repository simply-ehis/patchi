"""
Documentation claim validator.

Parses README and documentation files for factual claims about the project
(code features, API endpoints, supported formats, etc.), cross-references
each claim against the actual scanned code, and stores validated claims in
the brain for use by fix agents and contract inference.

This prevents the classic problem of docs saying "supports X" when X was
removed months ago.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS
from patchi.core.brain.route_mapper import RouteInfo
from patchi.core.brain.scanner import FileInfo

# ── Claim extraction ────────────────────────────────────────────────────────────

# Patterns that look like documented features in README files
_CLAIM_PATTERNS = [
    re.compile(r"(?:supports?|handles?|manages?|provides?|offers?|features?)\s+([^.,]+)", re.IGNORECASE),
    re.compile(r"- \[x\]\s*(.+)", re.IGNORECASE),  # checkbox done
    re.compile(r"\*\*(.+?)\*\*\s*(?:—|–|-|:)\s*.+", re.IGNORECASE),  # **Feature** — description
    re.compile(r"(?:API|endpoint|route)\s*[`:/]\s*([A-Za-z0-9_/{}]+)", re.IGNORECASE),  # inline API mentions
    re.compile(r"(?:CLI|command)\s*[`:]\s*([a-z][a-z0-9_-]+)", re.IGNORECASE),  # inline CLI mentions
]


def extract_claims(doc_path: Path) -> list[str]:
    """Parse a documentation file and return a list of raw claim strings."""
    if not doc_path.exists():
        return []
    try:
        text = doc_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    claims: list[str] = []
    for pattern in _CLAIM_PATTERNS:
        for m in pattern.finditer(text):
            claim = m.group(1).strip()
            if len(claim) > 15 and claim not in claims:
                claims.append(claim)
    return claims


def _tokenize(text: str) -> set[str]:
    """Split text into lowercase tokens for overlap matching."""
    return set(re.findall(r"[a-z][a-z0-9_]{2,}", text.lower()))


def _code_vocabulary(file_infos: list[FileInfo], routes: list[RouteInfo]) -> dict[str, list[str]]:
    """Build a token→evidence map from the actual codebase."""
    vocab: dict[str, list[str]] = {}
    for fi in file_infos:
        for token in _tokenize(fi.path):
            vocab.setdefault(token, []).append(f"file: {fi.path}")
        for func in fi.functions:
            for token in _tokenize(func.name):
                vocab.setdefault(token, []).append(f"file: {fi.path} function: {func.name}")
        for cls in fi.classes:
            for token in _tokenize(cls.name):
                vocab.setdefault(token, []).append(f"file: {fi.path} class: {cls.name}")
    for route in routes:
        for token in _tokenize(route.path):
            vocab.setdefault(token, []).append(f"route: {route.method} {route.path}")
    return vocab


def _route_segments(routes: list[RouteInfo]) -> set[str]:
    """Real URL path segments from the route table (structural facts)."""
    segs: set[str] = set()
    for r in routes:
        path = getattr(r, "path", "") or ""
        for s in path.split("/"):
            s = s.strip().lower()
            if len(s) >= 4:
                segs.add(s)
    return segs


def _cli_command_names() -> set[str]:
    """Real CLI command names from the registry (structural facts)."""
    try:
        from patchi.cli.registry import COMMANDS

        names: set[str] = set()
        for cmd in COMMANDS:
            name = getattr(cmd, "name", "") or ""
            if len(name) >= 2:
                names.add(name.lower())
            for alias in getattr(cmd, "aliases", None) or []:
                if len(alias) >= 2:
                    names.add(alias.lower())
        return names
    except Exception:
        return set()


def cross_reference_claim(
    claim: str,
    file_infos: list[FileInfo],
    routes: list[RouteInfo],
) -> tuple[bool, list[str]]:
    """
    Check if a claim is backed by actual code. Returns (verified, evidence).

    Part 7: one overlapping token is NOT proof (the old
    ``verified = len(evidence) >= 1``). A claim verifies only through a
    structural rule, recorded in the evidence as ``[check:...]``:
    - route-match: a claim token equals a real route path segment.
    - command-match: a claim token equals a real CLI command name.
    - symbol-corroboration: 2+ distinct claim tokens hit the SAME
      function/class/route item (one stray token never suffices).
    Bare filename-only hits never verify on their own.
    """
    claim_tokens = _tokenize(claim)
    if not claim_tokens:
        return False, []

    segments = _route_segments(routes)
    commands = _cli_command_names()

    evidence: list[str] = []
    checks: list[str] = []

    route_hits = sorted(t for t in claim_tokens if t in segments)
    if route_hits:
        checks.append("route-match")
        evidence.append(f"[check:route-match] segments={route_hits}")
    command_hits = sorted(t for t in claim_tokens if t in commands)
    if command_hits:
        checks.append("command-match")
        evidence.append(f"[check:command-match] commands={command_hits}")

    # Symbol corroboration: per-item distinct-token counts over
    # function/class/route items only (bare file tokens don't count).
    vocab = _code_vocabulary(file_infos, routes)
    scored: dict[str, set[str]] = {}
    for token in claim_tokens:
        for ev in vocab.get(token, []):
            if ev.startswith("route: ") or " function: " in ev or " class: " in ev:
                scored.setdefault(ev, set()).add(token)
    best = sorted(scored.items(), key=lambda kv: -len(kv[1]))
    if best and len(best[0][1]) >= 2:
        checks.append("symbol-corroboration")
        evidence.append(
            f"[check:symbol-corroboration] {best[0][0]} tokens={sorted(best[0][1])}"
        )

    # Context: top raw overlaps for the human reader (never verdicts).
    for ev, _ in best[1:4]:
        evidence.append(ev)

    verified = bool(checks)
    return verified, evidence[:6]


# ── Main validation entry point ────────────────────────────────────────────────


def validate_project_docs(
    root: Path,
    file_infos: list[FileInfo],
    routes: list[RouteInfo],
    ai_config: dict | None = None,
) -> dict[str, Any]:
    """
    Validate all documentation files in a project against scanned code.

    Returns a dict with:
      - validated_claims: list of {claim, evidence, verified}
      - stale_claims: list of {claim, reason} (claims that could not be verified)
      - summary: plain-English summary of doc health
    """
    # Find doc files (skip .venv, node_modules, __pycache__)
    _EXCLUDED_DIRS = DEFAULT_IGNORE_DIRS | {"files 6", ".vscode", ".idea"}

    doc_files = []
    for pattern in ("README*", "*.md", "docs/**/*.md"):
        if "*" in pattern:
            matched = list(root.glob(pattern))
            # Filter out excluded directories
            matched = [p for p in matched if not any(part in _EXCLUDED_DIRS for part in p.relative_to(root).parts)]
        else:
            p = root / pattern
            if p.exists():
                matched = [p]
            else:
                matched = []
        doc_files.extend(matched)
    doc_files = sorted(set(doc_files))

    all_claims: list[tuple[str, Path]] = []
    for doc_path in doc_files:
        for claim in extract_claims(doc_path):
            all_claims.append((claim, doc_path))

    result = {
        "validated_claims": [],
        "stale_claims": [],
        "summary": "",
        "doc_files_found": [str(p) for p in doc_files],
        "total_claims": 0,
    }

    for claim, doc_path in all_claims:
        verified, evidence = cross_reference_claim(claim, file_infos, routes)
        entry = {
            "claim": claim,
            "source": str(doc_path),
            "verified": verified,
            "evidence": evidence,
        }
        if verified:
            result["validated_claims"].append(entry)
        else:
            entry["reason"] = (
                "no route/command/symbol corroboration in code "
                "(single-token overlaps do not verify)"
            )
            result["stale_claims"].append(entry)

    result["total_claims"] = len(all_claims)
    result["summary"] = _build_summary(result)
    return result


def _build_summary(result: dict) -> str:
    total = result["total_claims"]
    validated = len(result["validated_claims"])
    stale = len(result["stale_claims"])
    doc_count = len(result["doc_files_found"])

    if total == 0:
        return f"Found {doc_count} doc file(s) but no verifiable claims."

    parts = [f"Verified {validated}/{total} claims across {doc_count} doc file(s)."]
    if stale:
        parts.append(f"{stale} claim(s) could not be verified against code")
    return " ".join(parts)
