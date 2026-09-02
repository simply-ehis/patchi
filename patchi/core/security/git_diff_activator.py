"""
Git Diff Activator — on-demand security domain activation from file changes.

When ``p scan --changed`` is used, this module:
  1. Reads changed files from ``git diff`` (or ``git log``)
  2. Maps each changed file to relevant security domains via path patterns,
     file extensions, and content heuristics
  3. Returns a scored list of domains to activate

This lets the scan run only the agents relevant to what actually changed,
cutting scan time from minutes to seconds for small diffs.

Usage::

    from patchi.core.security.git_diff_activator import activate_from_diff

    domains = activate_from_diff(root, commits=1)
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger("patchi.security.git_diff_activator")

_CACHE_FILE = ".patchi/diff_activation_cache.json"
_CACHE_TTL = 300  # 5 minutes max age even if HEAD unchanged


# ── Path → Domain Mapping ────────────────────────────────────────────────────

# Patterns: (glob-like substring match, domain, weight)
_PATH_DOMAIN_MAP: list[tuple[str, str, float]] = [
    # Auth / session
    ("auth", "authentication", 0.8),
    ("login", "authentication", 0.8),
    ("session", "session-management", 0.7),
    ("jwt", "jwt-security", 0.9),
    ("token", "jwt-security", 0.6),
    ("oauth", "authentication", 0.8),
    ("permission", "authorization", 0.8),
    ("role", "authorization", 0.7),
    ("admin", "authorization", 0.7),
    ("guard", "authorization", 0.6),
    ("middleware", "authentication", 0.5),
    # Injection / XSS
    ("query", "injection-sql", 0.6),
    ("sql", "injection-sql", 0.8),
    ("database", "injection-sql", 0.5),
    ("search", "xss-reflected", 0.4),
    ("template", "xss-stored", 0.4),
    ("render", "xss-dom", 0.4),
    ("markup", "xss-stored", 0.5),
    ("form", "csrf", 0.5),
    # Secrets / crypto
    ("secret", "secrets-management", 0.9),
    ("credential", "secrets-management", 0.9),
    ("key", "secrets-management", 0.6),
    ("env", "secrets-management", 0.5),
    ("encrypt", "cryptography", 0.8),
    ("decrypt", "cryptography", 0.8),
    ("hash", "cryptography", 0.7),
    ("ssl", "tls-ssl", 0.8),
    ("tls", "tls-ssl", 0.8),
    ("cert", "tls-ssl", 0.7),
    # Network / API
    ("api", "api-security", 0.5),
    ("route", "api-security", 0.4),
    ("endpoint", "api-security", 0.5),
    ("fetch", "ssrf", 0.4),
    ("request", "ssrf", 0.4),
    ("http", "ssrf", 0.3),
    ("cors", "cors", 0.9),
    ("header", "security-headers", 0.7),
    ("rate", "rate-limiting", 0.6),
    ("limit", "rate-limiting", 0.5),
    # Config / infra
    ("config", "configuration-hardening", 0.5),
    ("setting", "configuration-hardening", 0.4),
    ("docker", "container-security", 0.8),
    ("kubernetes", "kubernetes-security", 0.9),
    ("k8s", "kubernetes-security", 0.9),
    ("helm", "kubernetes-security", 0.7),
    ("terraform", "cloud-security", 0.8),
    ("cloud", "cloud-security", 0.6),
    ("infra", "container-security", 0.5),
    ("iac", "container-security", 0.7),
    # Dependencies
    ("requirements", "dependency-vulnerability", 0.7),
    ("package.json", "dependency-vulnerability", 0.7),
    ("Cargo.toml", "supply-chain", 0.7),
    ("go.mod", "supply-chain", 0.7),
    ("lock", "supply-chain", 0.5),
    # Business logic / privacy
    ("payment", "business-logic", 0.8),
    ("order", "business-logic", 0.7),
    ("cart", "business-logic", 0.6),
    ("privacy", "privacy-gdpr", 0.9),
    ("gdpr", "privacy-gdpr", 0.9),
    ("pii", "privacy-gdpr", 0.8),
    ("data", "data-layer", 0.4),
    ("audit", "audit-logging", 0.7),
    ("log", "audit-logging", 0.4),
    ("history", "audit-logging", 0.5),
    # File / upload
    ("upload", "file-handling", 0.8),
    ("file", "file-handling", 0.4),
    ("download", "file-handling", 0.6),
    ("path", "path-traversal", 0.5),
    ("static", "file-handling", 0.3),
]

# Extension → domain boost
_EXT_DOMAIN_MAP: list[tuple[str, str, float]] = [
    (".yaml", "configuration-hardening", 0.4),
    (".yml", "configuration-hardening", 0.4),
    (".toml", "supply-chain", 0.4),
    (".env", "secrets-management", 0.8),
    (".tf", "cloud-security", 0.9),
    (".hcl", "cloud-security", 0.7),
    (".sql", "injection-sql", 0.8),
    (".sh", "audit-logging", 0.3),
    (".dockerfile", "container-security", 0.8),
    (".go", "supply-chain", 0.3),
    (".rs", "supply-chain", 0.3),
    (".java", "supply-chain", 0.3),
    (".rb", "supply-chain", 0.3),
]

# Security-critical file names that always activate
_ALWAYS_ACTIVE: list[tuple[str, str, float]] = [
    ("Dockerfile", "container-security", 0.9),
    ("docker-compose", "container-security", 0.9),
    ("Makefile", "audit-logging", 0.3),
    (".github", "cicd-pipeline", 0.7),
    ("ci.yml", "cicd-pipeline", 0.8),
    ("cd.yml", "cicd-pipeline", 0.8),
]


@dataclass
class DiffActivationResult:
    """Result of git-diff-based domain activation."""

    changed_files: list[str] = field(default_factory=list)
    activated_domains: dict[str, float] = field(default_factory=dict)
    commits_analyzed: int = 0
    error: str = ""


def _get_head_hash(root: Path) -> str:
    """Get the current HEAD commit hash."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _load_cache(root: Path) -> dict:
    path = root / _CACHE_FILE
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(root: Path, data: dict) -> None:
    path = root / _CACHE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def get_changed_files(root: Path, commits: int = 1) -> list[str]:
    """Get files changed in the last N commits via git diff.

    Falls back to uncommitted changes if HEAD has no prior commits.
    """
    try:
        # Try diff against N commits back
        result = subprocess.run(
            ["git", "diff", "--name-only", f"HEAD~{commits}", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]

        # Fallback: uncommitted changes
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]

        # Fallback: staged changes
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]

        return []
    except Exception as exc:
        _log.warning("git diff failed: %s", exc)
        return []


def map_file_to_domains(file_path: str) -> dict[str, float]:
    """Map a single file path to domain scores."""
    scores: dict[str, float] = {}
    fp_lower = file_path.lower()

    # Check path patterns
    for pattern, domain, weight in _PATH_DOMAIN_MAP:
        if pattern in fp_lower:
            scores[domain] = max(scores.get(domain, 0), weight)

    # Check extension
    for ext, domain, weight in _EXT_DOMAIN_MAP:
        if fp_lower.endswith(ext):
            scores[domain] = max(scores.get(domain, 0), weight)

    # Check always-active names
    for name, domain, weight in _ALWAYS_ACTIVE:
        if name.lower() in fp_lower:
            scores[domain] = max(scores.get(domain, 0), weight)

    return scores


def activate_from_diff(
    root: Path,
    commits: int = 1,
    min_score: float = 0.4,
    max_domains: int = 20,
    use_cache: bool = True,
) -> DiffActivationResult:
    """Activate security domains based on git-diff changed files.

    Args:
        root: Project root
        commits: How many commits back to diff (1 = last commit only)
        min_score: Minimum domain score to activate
        max_domains: Maximum domains to activate
        use_cache: Whether to use persisted cache (default True)

    Returns:
        DiffActivationResult with activated domains and their scores
    """
    # ── Cache lookup ──────────────────────────────────────────────────────
    cache_key = f"{commits}:{min_score}:{max_domains}"
    if use_cache:
        head = _get_head_hash(root)
        cache = _load_cache(root)
        cached = cache.get(cache_key)
        if (
            cached
            and cached.get("head") == head
            and cached.get("uncommitted_count", 0) == 0
            and (time.time() - cached.get("ts", 0)) < _CACHE_TTL
        ):
            _log.debug("Using cached diff activation (head=%s)", head[:8])
            return DiffActivationResult(
                changed_files=cached["changed_files"],
                activated_domains={k: float(v) for k, v in cached["domains"].items()},
                commits_analyzed=commits,
            )

    changed = get_changed_files(root, commits)
    if not changed:
        return DiffActivationResult(error="No changed files found (not a git repo or no changes)")

    # Aggregate domain scores across all changed files
    all_scores: dict[str, float] = {}
    for fp in changed:
        file_scores = map_file_to_domains(fp)
        for domain, score in file_scores.items():
            all_scores[domain] = max(all_scores.get(domain, 0), score)

    # Filter by minimum score
    activated = {d: s for d, s in all_scores.items() if s >= min_score}

    # Sort by score descending and limit
    sorted_domains = sorted(activated.items(), key=lambda x: -x[1])
    if len(sorted_domains) > max_domains:
        sorted_domains = sorted_domains[:max_domains]
        activated = dict(sorted_domains)

    _log.info(
        "Git-diff activation: %d changed files → %d domains (from %d total signals)",
        len(changed),
        len(activated),
        len(all_scores),
    )

    result = DiffActivationResult(
        changed_files=changed,
        activated_domains=activated,
        commits_analyzed=commits,
    )

    # ── Persist cache ─────────────────────────────────────────────────────
    if use_cache:
        head = _get_head_hash(root)
        # Count uncommitted changes to invalidate cache on dirty tree
        uncommitted = 0
        try:
            u = subprocess.run(
                ["git", "diff", "--name-only", "HEAD"],
                capture_output=True,
                text=True,
                cwd=str(root),
                timeout=5,
            )
            if u.returncode == 0:
                uncommitted = len([line for line in u.stdout.strip().splitlines() if line.strip()])
        except Exception as _exc:
            _log.warning('activate_from_diff failed: %s', _exc)
        cache = _load_cache(root)
        cache[cache_key] = {
            "head": head,
            "ts": time.time(),
            "changed_files": changed,
            "domains": dict(activated.items()),
            "uncommitted_count": uncommitted,
        }
        _save_cache(root, cache)

    return result


def read_changed_file_content(root: Path, file_path: str, max_lines: int = 100) -> str:
    """Read the content of a changed file for deeper analysis."""
    full = root / file_path
    if not full.is_file():
        return ""
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[:max_lines])
    except Exception:
        return ""
