"""
Secrets detection (Dream Assistant spec — Audit/Live Mode security sweep).

A fast, low-false-positive regex sweep over source files. If `gitleaks`
or `semgrep` is installed it can be used instead (see `scan_secrets`).
Both `p audit` and `p watch` reuse this so detection stays consistent.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from patchi.core.brain.ast_utils import find_assignments
from patchi.core.brain.code_query import string_literals
from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS, detect_language

# Source-ish extensions worth scanning for secrets.
_SCAN_EXTS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".env",
    ".toml",
    ".yaml",
    ".yml",
    ".json",
    ".cfg",
    ".ini",
    ".xml",
    ".sh",
    ".bash",
    ".ps1",
    ".sql",
    ".pem",
    ".key",
    ".crt",
    ".pub",
    ".p12",
    ".keystore",
}

_SKIP_DIRS = DEFAULT_IGNORE_DIRS

# Provider token shapes: (rule, prefix, min_token_len). Matched against parsed
# string literals (never comments/raw text) plus an entropy gate.
_PROVIDER_TOKENS: list[tuple[str, str, int]] = [
    ("aws_access_key_id", "AKIA", 20),
    ("openai_key", "sk-", 20),
    ("github_pat", "ghp_", 20),
    ("github_oauth", "gho_", 20),
    ("slack_token", "xox", 12),
    ("google_api", "AIza", 35),
]
_PRIVATE_KEY_MARKERS = ("PRIVATE KEY",)
_GENERIC_NAME_MARKERS = ("api_key", "apikey", "secret", "token", "passwd", "password")
_KEY_EXTENSIONS = {".pem", ".key", ".keystore", ".p12", ".pfx"}


def _entropy(text: str) -> float:
    """Shannon entropy in bits/char (high randomness ⇒ likely a real token)."""
    import math

    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _provider_hit(value: str) -> str | None:
    """Rule name when a literal value looks like a provider token, else None."""
    upper = value.upper()
    for rule, prefix, min_len in _PROVIDER_TOKENS:
        if prefix.upper() not in upper:
            continue
        for token in value.split():
            if prefix.upper() in token.upper() and len(token) >= min_len:
                if _entropy(token) >= 3.0:
                    return rule
    return None


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
        if p.suffix.lower() not in _SCAN_EXTS and p.name.lower() not in _SCAN_EXTS:
            continue
        if p.stat().st_size > 1_000_000:
            continue
        out.append(p)
    return out


def _literal_scan(files: list[Path]) -> list[SecretHit]:
    """Structural secret sweep: parsed literals + assignments + entropy.

    Provider tokens match fixed prefixes inside string literals (comments can
    never match); generic keys match secret-ish assignment targets with
    quoted values; key files match by extension. Entropy gates tokens.
    """
    hits: list[SecretHit] = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            _log.warning("_sweep_files failed: %s", e)
            continue
        lines = text.splitlines()
        flagged: set[int] = set()

        def _hit(line: int, rule: str, _f=f, _lines=lines, _flagged=flagged) -> None:
            if line in _flagged or not (0 < line <= len(_lines)):
                return
            _flagged.add(line)
            snippet = _lines[line - 1].strip()[:120]
            hits.append(SecretHit(path=_f.as_posix(), line=line, rule=rule, snippet=snippet))

        try:
            lang = detect_language(f)
        except Exception:
            lang = None
        literals: list[tuple[str, int]] = []
        if lang is not None:
            try:
                literals = string_literals(text, lang)
            except Exception:
                literals = []
        for value, line in literals:
            rule = _provider_hit(value)
            if rule is not None:
                _hit(line, rule)
                continue
            if any(m in value for m in _PRIVATE_KEY_MARKERS):
                _hit(line, "private_key")
        # Generic keys: secret-ish assignment targets with quoted values
        if lang is not None:
            try:
                for assignment in find_assignments(text, lang):
                    target = str(assignment.get("target", "")).lower()
                    if not any(m in target for m in _GENERIC_NAME_MARKERS):
                        continue
                    raw = str(assignment.get("value", "")).strip()
                    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'`":
                        if len(raw) - 2 >= 8:
                            _hit(int(assignment.get("line", 0) or 0), "generic_api_key")
            except Exception:
                pass
        # Config/env-style KEY="VALUE" lines (no parser exists — plain splitting).
        # Values must be quoted, matching the original quoted-value bar.
        # Full-line comments can't match (parsed literals/assignments above
        # already exclude comments structurally).
        for i, line in enumerate(lines, start=1):
            if i in flagged or "=" not in line:
                continue
            if line.strip()[:1] in ("#",):
                continue
            if line.strip().startswith("//"):
                continue
            name, _, raw_value = line.partition("=")
            name = name.strip().lower()
            quoted = raw_value.strip()
            if not (len(quoted) >= 2 and quoted[0] == quoted[-1] and quoted[0] in "\"'"):
                continue
            value = quoted[1:-1]
            if len(value) >= 8 and any(m in name for m in _GENERIC_NAME_MARKERS):
                _hit(i, "generic_api_key")
                continue
            rule = _provider_hit(value)
            if rule is not None:
                _hit(i, rule)
        # Key material files are findings by nature
        if f.suffix.lower() in _KEY_EXTENSIONS and text.strip():
            _hit(1, "private_key")
    return hits


_regex_scan = _literal_scan


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
                [
                    "gitleaks",
                    "detect",
                    "--source",
                    str(target),
                    "--no-banner",
                    "--report-format",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            # gitleaks exits 1 when leaks found; parse JSON report from stdout.
            # On Windows, stdout can be empty while stderr contains ANSI escape
            # codes — only parse stdout to avoid "Expecting value" JSON errors.
            import json

            try:
                data = json.loads(proc.stdout or "[]")
                return [
                    SecretHit(
                        path=d.get("file", "?"),
                        line=int(d.get("line", 0)),
                        rule=d.get("rule", "gitleaks"),
                        snippet=(d.get("match") or "")[:120],
                    )
                    for d in data
                    if isinstance(d, dict)
                ]
            except Exception as e:
                _log.warning("scan_secrets failed: %s", e)
        except Exception as e:
            _log.warning("scan_secrets failed: %s", e)

    return _regex_scan(files)
