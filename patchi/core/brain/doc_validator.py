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
    re.compile(
        r"(?:supports?|handles?|manages?|provides?|offers?|features?)\s+([^.,]+)", re.IGNORECASE
    ),
    re.compile(r"- \[x\]\s*(.+)", re.IGNORECASE),  # checkbox done
    re.compile(r"\*\*(.+?)\*\*\s*(?:—|–|-|:)\s*.+", re.IGNORECASE),  # **Feature** — description
    re.compile(
        r"(?:API|endpoint|route)\s*[`:/]\s*([A-Za-z0-9_/{}]+)", re.IGNORECASE
    ),  # inline API mentions
    re.compile(
        r"(?:CLI|command)\s*[`:]\s*([a-z][a-z0-9_-]+)", re.IGNORECASE
    ),  # inline CLI mentions
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


def cross_reference_claim(
    claim: str,
    file_infos: list[FileInfo],
    routes: list[RouteInfo],
) -> tuple[bool, list[str]]:
    """
    Check if a claim is backed by actual code.
    Uses token-overlap matching instead of hardcoded keyword lists.
    Returns (verified, evidence_list).
    """
    claim_tokens = _tokenize(claim)
    if not claim_tokens:
        return False, []

    vocab = _code_vocabulary(file_infos, routes)
    evidence: list[str] = []
    scored: dict[str, float] = {}

    for token in claim_tokens:
        for ev in vocab.get(token, []):
            scored[ev] = scored.get(ev, 0) + 1

    # Sort by overlap count, take top matches
    for ev, _ in sorted(scored.items(), key=lambda x: -x[1]):
        if ev not in evidence:
            evidence.append(ev)
        if len(evidence) >= 5:
            break

    verified = len(evidence) >= 1
    return verified, evidence[:5]


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
            matched = [
                p
                for p in matched
                if not any(part in _EXCLUDED_DIRS for part in p.relative_to(root).parts)
            ]
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
