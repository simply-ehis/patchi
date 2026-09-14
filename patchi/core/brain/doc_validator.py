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
from dataclasses import dataclass
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


# ── Citation drift detection ────────────────────────────────────────────────────


@dataclass
class DriftIssue:
    """A documentation reference that points to nonexistent or moved code."""

    type: str  # always "citation"
    reference: str  # the raw reference (path or symbol name)
    status: str  # "valid" | "missing" | "moved"
    suggestion: str  # human-readable hint (e.g. closest match or empty)
    source: str = ""  # doc file where the reference was found


# Paths referenced in docs — relative paths ending in a code extension
_RE_FILE_PATH = re.compile(
    r"[`\"\']?((?:[A-Za-z0-9_./\\-]+\.)"
    r"(?:py|js|ts|go|rs))"
    r"[`\"\']?",
)

# Backtick-wrapped or function-call patterns: `func_name` or name()
# Exclude dots in backtick captures to avoid matching file paths like `foo.py`
_RE_SYMBOL = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]*(?:\(\))?)`"
    r"|(?<!\w)([A-Za-z_][A-Za-z0-9_]*)(?=\(\))",
)


def _extract_citations(doc_text: str) -> tuple[list[str], list[str]]:
    """Return (file_paths, symbol_names) referenced in doc text."""
    paths = []
    for m in _RE_FILE_PATH.finditer(doc_text):
        p = m.group(1).strip()
        if p not in paths:
            paths.append(p)

    symbols = []
    for m in _RE_SYMBOL.finditer(doc_text):
        name = m.group(1) or m.group(2)
        if name:
            # Strip trailing () for lookup
            bare = name.rstrip("()")
            if bare not in symbols:
                symbols.append(bare)
    return paths, symbols


def _build_symbol_index(
    file_infos: list[FileInfo],
) -> dict[str, list[str]]:
    """Map lowercase symbol name → list of file paths where it's defined."""
    index: dict[str, list[str]] = {}
    for fi in file_infos:
        for func in fi.functions:
            key = func.name.lower()
            index.setdefault(key, []).append(fi.path)
        for cls in fi.classes:
            key = cls.name.lower()
            index.setdefault(key, []).append(fi.path)
    return index


def _find_closest(name: str, candidates: list[str], max_dist: int = 2) -> str:
    """Return the closest candidate by character-overlap distance, or empty string.

    The distance is: max(len_a, len_b) - shared_characters_at_same_position.
    Only suggestions within *max_dist* are returned.
    """
    if not candidates:
        return ""
    lower = name.lower()
    best, best_dist = "", max_dist + 1
    for c in candidates:
        cl = c.lower()
        common = sum(1 for a, b in zip(lower, cl, strict=False) if a == b)
        dist = max(len(lower), len(cl)) - common
        if dist < best_dist:
            best, best_dist = c, dist
    return best if best_dist <= max_dist else ""


def _check_citation_drift(
    doc_text: str,
    project_root: Path,
    file_infos: list[FileInfo],
    doc_source: str = "",
) -> list[DriftIssue]:
    """Detect references in docs to code that no longer exists or has moved.

    Checks:
      - File paths: does the referenced file exist on disk?
      - Symbols: does the referenced function/class exist in the scanned codebase?

    Returns a list of DriftIssue objects.  Only non-valid issues are returned
    to keep output focused on problems.
    """
    paths, symbols = _extract_citations(doc_text)
    issues: list[DriftIssue] = []

    # ── File path checks ───────────────────────────────────────────────────
    known_files = {fi.path for fi in file_infos}
    for ref in paths:
        ref_fwd = ref.replace("\\", "/").lstrip("./")
        # Check exact match first
        if ref_fwd in known_files or (project_root / ref_fwd).exists():
            continue
        # Check if file exists anywhere under project root (moved)
        basename = Path(ref_fwd).name
        moved_candidates = [
            fi.path for fi in file_infos if Path(fi.path).name == basename
        ]
        if moved_candidates:
            issues.append(DriftIssue(
                type="citation",
                reference=ref,
                status="moved",
                suggestion=f"moved to: {moved_candidates[0]}",
                source=doc_source,
            ))
        else:
            issues.append(DriftIssue(
                type="citation",
                reference=ref,
                status="missing",
                suggestion="file not found in codebase",
                source=doc_source,
            ))

    # ── Symbol checks ──────────────────────────────────────────────────────
    sym_index = _build_symbol_index(file_infos)
    all_symbol_names = list(sym_index.keys())
    for sym in symbols:
        key = sym.lower()
        if key in sym_index:
            continue  # symbol exists — valid
        suggestion = _find_closest(sym, all_symbol_names)
        issues.append(DriftIssue(
            type="citation",
            reference=sym,
            status="missing",
            suggestion=f"did you mean: {suggestion}" if suggestion else "symbol not found",
            source=doc_source,
        ))

    return issues


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
    for pattern in (
        "README*", "*.md", "*.txt", "*.rst", "*.adoc", "*.asciidoc", "*.mdown",
        "docs/**/*.md", "docs/**/*.txt", "docs/**/*.rst",
    ):
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

    # ── Citation drift detection ────────────────────────────────────────────
    all_drift: list[DriftIssue] = []
    for doc_path in doc_files:
        try:
            doc_text = doc_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(doc_path.relative_to(root))
        all_drift.extend(_check_citation_drift(doc_text, root, file_infos, doc_source=rel))

    result = {
        "validated_claims": [],
        "stale_claims": [],
        "citation_drift": [
            {"type": d.type, "reference": d.reference, "status": d.status,
             "suggestion": d.suggestion, "source": d.source}
            for d in all_drift
        ],
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
    drift_count = len(result.get("citation_drift", []))

    if total == 0 and drift_count == 0:
        return f"Found {doc_count} doc file(s) but no verifiable claims."

    parts = []
    if total > 0:
        parts.append(f"Verified {validated}/{total} claims across {doc_count} doc file(s).")
        if stale:
            parts.append(f"{stale} claim(s) could not be verified against code")
    if drift_count:
        parts.append(f"{drift_count} citation drift issue(s) detected (missing/moved references)")
    return " ".join(parts)
