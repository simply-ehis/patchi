"""
Git-aware intelligence for Patchi.

Provides:
  - Incremental scan: only scan files changed since last scan (via git diff)
  - Blame integration: trace which commit introduced a finding
  - Changelog generation: summarize what changed between scans

Uses subprocess to call git — no Python git library required.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from patchi.core.agents.base import Finding


import logging
_log = logging.getLogger("patchi.brain.git_aware")

def _git(args: list[str], root: Path) -> str | None:
    """Run a git command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception as e:
        _log.debug("_git failed: %s", e)
        return None


def is_git_repo(root: Path) -> bool:
    """Check if the project is a git repository."""
    return _git(["rev-parse", "--is-inside-work-tree"], root) == "true"


def get_changed_files(root: Path, since: str = "HEAD") -> list[str]:
    """
    Get list of files changed since a ref (commit, tag, branch).
    Default: changes since last commit.
    Returns relative paths.
    """
    output = _git(["diff", "--name-only", since], root)
    if output is None:
        # Try diffing against empty tree (all files)
        output = _git(["diff", "--name-only", "--diff-filter=ACMR", "HEAD~1"], root)
    if output is None:
        return []

    # Also include untracked files
    untracked = _git(["ls-files", "--others", "--exclude-standard"], root)

    files = [f for f in output.splitlines() if f.strip()]
    if untracked:
        files.extend(f for f in untracked.splitlines() if f.strip())

    return list(set(files))


def get_changed_since_scan(root: Path, last_scan_time: float | None = None) -> list[str]:
    """
    Get files changed since the last scan timestamp.
    Falls back to git log if timestamps aren't available.
    """
    if last_scan_time is None:
        # No previous scan — return all files
        return []

    # Use git log to find commits since last scan
    import time

    since_date = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(last_scan_time))

    output = _git(["log", "--since=" + since_date, "--name-only", "--pretty=format:"], root)
    if output is None:
        return []

    files = [f for f in output.splitlines() if f.strip()]
    return list(set(files))


def blame_line(file_path: str, line: int, root: Path) -> dict | None:
    """
    Git blame a specific line. Returns:
    {"commit": "abc123", "author": "Name", "date": "2024-01-01", "summary": "msg"}
    """
    output = _git(["blame", "-L", f"{line},{line}", "--porcelain", file_path], root)
    if not output:
        return None

    result: dict[str, str] = {}
    for line_text in output.splitlines():
        # Porcelain format: first line is "<hash> <orig-line> <final-line> <count>"
        # No "commit " prefix — the hash IS the first token on the first line.
        if not result.get("commit") and line_text and not line_text.startswith("\t"):
            parts = line_text.split()
            if parts and len(parts[0]) == 40 and all(c in "0123456789abcdef" for c in parts[0]):
                result["commit"] = parts[0]
        elif line_text.startswith("author "):
            result["author"] = line_text[7:]
        elif line_text.startswith("author-time "):
            import time

            ts = int(line_text[12:])
            result["date"] = time.strftime("%Y-%m-%d", time.localtime(ts))
        elif line_text.startswith("summary "):
            result["summary"] = line_text[8:]

    return result if result.get("commit") else None


def annotate_findings_with_blame(
    findings: list, root: Path, max_workers: int = 4
) -> int:
    """
    Enrich findings with git blame information.

    For each finding with a file + line, runs `git blame` and stores
    result in finding.extra["blame"] as {"commit", "author", "date", "summary"}.

    Uses parallel processing for speed. Skips non-git repos silently.
    Returns count of annotated findings.
    """
    if not is_git_repo(root):
        return 0

    annotated = 0
    import concurrent.futures

    def _blame_one(f: Finding) -> Finding:
        if not f.file or f.line <= 0:
            return f
        try:
            info = blame_line(f.file, f.line, root)
            if info:
                f.extra["blame"] = info
        except Exception as e:
            _log.debug("_blame_one failed: %s", e)
        return f

    batch = [f for f in findings if isinstance(f, Finding) and f.file and f.line > 0]
    if not batch:
        return 0

    # Cap per-agent blame calls to avoid excessive subprocess overhead on Windows
    if len(batch) > 200:
        batch = batch[:200]

    if len(batch) == 1 or max_workers <= 1:
        for f in batch:
            _blame_one(f)
            if f.extra.get("blame"):
                annotated += 1
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            for f in pool.map(_blame_one, batch):
                if f.extra.get("blame"):
                    annotated += 1

    return annotated


def changelog(root: Path, since: str = "HEAD~10") -> list[dict]:
    """
    Generate a changelog from git log.
    Returns list of {"hash", "author", "date", "summary", "files"}.
    """
    output = _git(
        ["log", since, "--pretty=format:%H|%an|%ad|%s", "--date=short"],
        root,
    )
    if not output:
        return []

    entries = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 3)
        if len(parts) < 4:
            continue

        commit_hash, author, date, summary = parts

        # Get files changed in this commit
        files_output = _git(["diff-tree", "--no-commit-id", "-r", "--name-only", commit_hash], root)
        files = [f for f in (files_output or "").splitlines() if f.strip()]

        entries.append(
            {
                "hash": commit_hash[:8],
                "author": author,
                "date": date,
                "summary": summary,
                "files": files[:20],  # Cap at 20 files
            }
        )

    return entries
