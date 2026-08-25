"""
Secrets detection (Dream Assistant spec — Audit/Live Mode security sweep).

A fast, low-false-positive regex sweep over source files. If `gitleaks`
or `semgrep` is installed it can be used instead (see `scan_secrets`).
Both `p audit` and `p watch` reuse this so detection stays consistent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Source-ish extensions worth scanning for secrets.
_SCAN_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".env", ".toml", ".yaml", ".yml",
    ".json", ".cfg", ".ini", ".xml", ".sh", ".bash", ".ps1", ".sql",
    ".pem", ".key", ".crt", ".pub", ".p12", ".keystore",
}
from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

_SKIP_DIRS = DEFAULT_IGNORE_DIRS

# (rule name, compiled pattern)
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("github_pat", re.compile(r"(?i)ghp_[A-Za-z0-9]{20,}")),
    ("github_oauth", re.compile(r"(?i)gho_[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"(?i)xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google_api", re.compile(r"(?i)AIza[0-9A-Za-z_\-]{35}")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]


import logging

_log = logging.getLogger("patchi.brain.secrets")

@dataclass
class SecretHit:
    path: str
    line: int
    rule: str
    snippet: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line} [{self.rule}] {self.snippet}"


def _candidate_files(root: Path, paths: list[str] | None) -> list[Path]:
    if paths:
        out = []
        for p in paths:
            pp = Path(p)
            if not pp.is_absolute():
                pp = root / p
            if pp.is_dir():
                out.extend(_walk(pp))
            elif pp.is_file():
                out.append(pp)
        return out
    return _walk(root)


# Patchi's own security knowledge-base (fix-playbooks/domains YAML files) is
# full of deliberately-sampled example secrets and must never be reported as a
# real leak when Patchi scans itself (or a repo that vendors it).
_KNOWLEDGE_BASE_SEGMENTS = ("patchi/core/security/fix-playbooks", "patchi/core/security/domains")


def _walk(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        # Skip Patchi's own playbook/domain knowledge base (example secrets).
        rel = p.as_posix()
        if any(seg in rel for seg in _KNOWLEDGE_BASE_SEGMENTS):
            continue
        if p.suffix.lower() not in _SCAN_EXTS:
            continue
        if p.stat().st_size > 1_000_000:
            continue
        out.append(p)
    return out


def _regex_scan(files: list[Path]) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for f in files:
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception as e:
            _log.warning("_regex_scan failed: %s", e)
            continue
        for i, line in enumerate(lines, start=1):
            for rule, pat in _PATTERNS:
                m = pat.search(line)
                if m:
                    snippet = line.strip()[:120]
                    hits.append(SecretHit(path=f.as_posix(), line=i, rule=rule, snippet=snippet))
                    break
    return hits


def scan_secrets(root: Path, paths: list[str] | None = None) -> list[SecretHit]:
    """
    Scan for secrets. Prefers gitleaks/semgrep if installed, else the
    built-in regex sweep. `paths` limits the scan (used by watch mode on
    changed files only).
    """
    root = Path(root)
    files = _candidate_files(root, paths)

    # Prefer gitleaks if available.
    if shutil.which("gitleaks"):
        try:
            if not files:
                return _regex_scan(files)
            target = files[0].parent if paths else root
            proc = subprocess.run(
                ["gitleaks", "detect", "--source", str(target), "--no-banner",
                 "--report-format", "json"],
                capture_output=True, text=True, timeout=120,
            )
            # gitleaks exits 1 when leaks found; parse JSON report from stderr/stdout.
            text = proc.stdout or proc.stderr
            import json

            try:
                data = json.loads(text)
                return [
                    SecretHit(path=d.get("file", "?"), line=int(d.get("line", 0)),
                              rule=d.get("rule", "gitleaks"), snippet=(d.get("match") or "")[:120])
                    for d in data if isinstance(d, dict)
                ]
            except Exception as e:
                _log.warning("scan_secrets failed: %s", e)
        except Exception as e:
            _log.warning("scan_secrets failed: %s", e)

    return _regex_scan(files)
