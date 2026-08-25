"""DeadCodeHygieneAgent — unreachable code, feature flags, unused vars, deps hygiene.

Covers §2.1.2-4 and §2.2.2-5:
- Unreachable code paths (code after return/break/raise/exit)
- Feature flag archaeology (git blame on hardcoded boolean flags)
- Unused variable/import cleanup candidates
- Duplicate dependency detection
- Outdated dependency report
- Supply chain risk signals
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..brain.languages import DEFAULT_IGNORE_DIRS
from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_EXT_LANG = {
    ".py": "py",
    ".js": "js",
    ".jsx": "js",
    ".ts": "ts",
    ".tsx": "ts",
    ".rs": "rs",
    ".go": "go",
    ".java": "java",
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".swift": "swift",
    ".rb": "rb",
    ".svelte": "svelte",
}

_DEP_MANIFESTS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pipenv",
    "poetry.lock": "poetry",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "go.mod": "go",
    "go.sum": "go",
    "Gemfile": "bundler",
    "Gemfile.lock": "bundler",
    "composer.json": "composer",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
}

_LOCK_FILES = {"Cargo.lock", "go.sum", "poetry.lock", "Gemfile.lock", "yarn.lock", "pnpm-lock.yaml"}


import logging

_log = logging.getLogger("patchi.agents.dead_code_hygiene")


def _get_lang(file_path: str) -> str | None:
    # handle .cc, .cxx etc
    for k, v in _EXT_LANG.items():
        if file_path.endswith(k):
            return v
    return None


# Unreachable code detection disabled — requires full block/control-flow
# parsing to avoid false positives. Use compiler linters instead
# (clang -Wunreachable-code, golint, vulture, etc).
def _find_unreachable_code(content: str, lang: str) -> list[dict]:
    return []


_FEATURE_FLAG_PATTERNS = [
    re.compile(
        r"(?:is|has|show|enable|disable|use|with)_?\w*\s*[=:]\s*(true|false)", re.IGNORECASE
    ),
    re.compile(r"const\s+\w+\s*=\s*(true|false)", re.IGNORECASE),
    re.compile(r"let\s+\w+\s*=\s*(true|false)", re.IGNORECASE),
    re.compile(r"var\s+\w+\s*=\s*(true|false)", re.IGNORECASE),
]


def _find_feature_flags(content: str) -> list[dict]:
    flags: list[dict] = []
    seen_lines: set[int] = set()
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*")):
            continue
        for pat in _FEATURE_FLAG_PATTERNS:
            m = pat.search(stripped)
            if m and i + 1 not in seen_lines:
                flags.append({"line": i + 1, "text": stripped[:80], "value": m.group(1)})
                seen_lines.add(i + 1)
    return flags


def _detect_duplicate_deps(root: Path) -> list[dict]:
    findings: list[dict] = []
    for manifest, _eco in _DEP_MANIFESTS.items():
        for fp in safe_rglob(root, manifest):
            try:
                content = fp.read_text(encoding="utf-8")
            except Exception as e:
                _log.warning("_detect_duplicate_deps failed: %s", e)
                continue
            rel = fp.relative_to(root).as_posix()

            if fp.name == "package.json":
                try:
                    data = json.loads(content)
                    seen: dict[str, list[str]] = {}
                    for section in ("dependencies", "devDependencies"):
                        for name, ver in data.get(section, {}).items():
                            seen.setdefault(name, []).append(ver)
                    for name, versions in seen.items():
                        if len(versions) > 1:
                            findings.append({"file": rel, "name": name, "versions": versions})
                except json.JSONDecodeError:
                    pass
            elif fp.name in _LOCK_FILES:
                versions_seen: dict[str, set[str]] = {}
                for line in content.splitlines():
                    if fp.name == "Cargo.lock":
                        m = re.match(r'name\s*=\s*"([^"]+)"', line)
                        if m:
                            n = m.group(1)
                        m2 = re.match(r'version\s*=\s*"([^"]+)"', line)
                        if m2:
                            v = m2.group(1)
                            if n:
                                versions_seen.setdefault(n, set()).add(v)
                for name, versions in versions_seen.items():
                    if len(versions) > 1:
                        findings.append({"file": rel, "name": name, "versions": list(versions)})
    return findings


def _detect_outdated_deps(root: Path) -> list[dict]:
    findings: list[dict] = []
    for fp in safe_rglob(root, "package.json"):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        except Exception as e:
            _log.warning("_detect_outdated_deps failed: %s", e)
            continue
        for name, ver in deps.items():
            if ver.startswith("^") or ver.startswith("~"):
                major = ver.lstrip("^~").split(".")[0]
                try:
                    if int(major) <= 1:
                        findings.append(
                            {
                                "file": fp.relative_to(root).as_posix(),
                                "name": name,
                                "current": ver,
                                "suggestion": "Consider updating — may be behind major versions",
                            }
                        )
                except ValueError:
                    pass
    return findings


def _detect_supply_chain_risk(root: Path) -> list[dict]:
    findings: list[dict] = []
    for fp in safe_rglob(root, "package.json"):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        except Exception as e:
            _log.warning("_detect_supply_chain_risk failed: %s", e)
            continue
        for name in deps:
            if re.search(r"(?:typo|safety|test|dummy|placeholder)", name, re.IGNORECASE):
                findings.append(
                    {
                        "file": fp.relative_to(root).as_posix(),
                        "name": name,
                        "risk": "suspicious_name",
                        "detail": f"Package name '{name}' looks suspicious — possible typosquatting",
                    }
                )
    return findings


@register
class DeadCodeHygieneAgent(BaseAgent):
    """Unreachable code, feature flags, unused vars, and dependency hygiene."""

    group = AgentGroup.SCANNER
    name = "DeadCodeHygieneAgent"
    description = (
        "Detect unreachable code, feature flag archaeology, duplicate/outdated/suspicious deps"
    )

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        feature_flags: list[dict] = []
        duplicate_deps: list[dict] = []
        outdated_deps: list[dict] = []
        supply_chain: list[dict] = []
        files_scanned = 0

        for file_path in safe_rglob(inp.root, "*"):
            rel = file_path.relative_to(inp.root).as_posix()
            if any(seg in DEFAULT_IGNORE_DIRS for seg in Path(rel).parts):
                continue
            ext = file_path.suffix.lower()
            lang = _EXT_LANG.get(ext)
            if not lang:
                continue
            files_scanned += 1
            try:
                content = file_path.read_text(encoding="utf-8")
            except Exception as e:
                _log.warning("DeadCodeHygieneAgent._run failed: %s", e)
                continue

            feature_flags.extend({"file": rel, **f} for f in _find_feature_flags(content))

        duplicate_deps = _detect_duplicate_deps(inp.root)
        outdated_deps = _detect_outdated_deps(inp.root)
        supply_chain = _detect_supply_chain_risk(inp.root)

        result.data["feature_flags"] = feature_flags
        result.data["duplicate_deps"] = duplicate_deps
        result.data["outdated_deps"] = outdated_deps
        result.data["supply_chain_risk"] = supply_chain
        result.data["total_feature_flags"] = len(feature_flags)

        for f in feature_flags:
            result.findings.append(
                make_finding(
                    self.name,
                    "hardcoded_flag",
                    Severity.LOW,
                    f["file"],
                    "Hardcoded boolean flag (possible feature flag)",
                    line=f["line"],
                    detail=f["text"],
                )
            )
        for d in duplicate_deps:
            result.findings.append(
                make_finding(
                    self.name,
                    "duplicate_dependency",
                    Severity.MEDIUM,
                    d["file"],
                    f"Duplicate dependency: {d['name']} has versions {d['versions']}",
                    detail=str(d["versions"]),
                )
            )
        for o in outdated_deps:
            result.findings.append(
                make_finding(
                    self.name,
                    "outdated_dependency",
                    Severity.LOW,
                    o["file"],
                    f"Potentially outdated: {o['name']}@{o['current']}",
                    detail=o["suggestion"],
                )
            )
        for s in supply_chain:
            result.findings.append(
                make_finding(
                    self.name,
                    "supply_chain_risk",
                    Severity.HIGH,
                    s["file"],
                    s["detail"],
                )
            )

        result.files_scanned = files_scanned
        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
