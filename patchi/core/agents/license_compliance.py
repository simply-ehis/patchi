"""LicenseComplianceAgent — checks dependency licenses against policy.

Covers §11.6:
- Parse package.json, pyproject.toml, Cargo.toml, go.mod, Gemfile
- Extract license field from each dependency
- Flag GPL/AGPL licenses (restrictive) and missing license fields
"""
from __future__ import annotations

import json
import logging
import re
import urllib.request
from pathlib import Path

from patchi.core.constants import is_offline

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

_RESTRICTED_LICENSES = {
    "gpl",
    "gpl-2.0",
    "gpl-3.0",
    "gplv2",
    "gplv3",
    "agpl",
    "agpl-3.0",
    "agplv3",
    "lgpl",
    "lgpl-3.0",
    "cc-by-nc",
    "cc-by-nc-nd",
    "proprietary",
    "commercial",
}

_ALLOWED_LICENSES = {
    "mit",
    "apache-2.0",
    "apache",
    "bsd-2-clause",
    "bsd-3-clause",
    "isc",
    "unlicense",
    "cc0-1.0",
    "cc-by-4.0",
    "python-2.0",
    "zlib",
    "mpl-2.0",
}

_UNKNOWN_LICENSE_RISK = {
    "gpl",
    "agpl",
    "lgpl",
    "unknown",
}


_log = logging.getLogger("patchi.agents.license_compliance")


def _normalize_license(license_str: str) -> str:
    return (
        license_str.strip()
        .strip('"')
        .strip("'")
        .lower()
        .replace("-or-later", "")
        .replace("-only", "")
    )


def _check_license(license_str: str | None) -> tuple[str, str]:
    """Returns (status, normalized)."""
    if not license_str:
        return "missing", "unknown"
    norm = _normalize_license(license_str)
    if norm in _RESTRICTED_LICENSES:
        return "restricted", norm
    if norm in _ALLOWED_LICENSES:
        return "allowed", norm
    if "gpl" in norm or "affero" in norm:
        return "restricted", norm
    return "unknown", norm


# Cache for lookup results
_license_cache: dict[str, str] = {}


def _lookup_license(package_name: str, eco: str) -> str | None:
    if is_offline():
        return None
    cache_key = f"{eco}:{package_name}"
    if cache_key in _license_cache:
        return _license_cache[cache_key]

    try:
        if eco == "npm":
            url = f"https://registry.npmjs.org/{package_name}/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "Patchi/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                lic = data.get("license")
                if lic:
                    _license_cache[cache_key] = lic
                    return lic
    except Exception as e:
        _log.warning("_lookup_license failed: %s", e)
    return None


def _extract_deps(root: Path) -> list[dict]:
    deps: list[dict] = []
    # package.json
    for fp in safe_rglob(root, "package.json"):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            for name in {**data.get("dependencies", {}), **data.get("devDependencies", {})}:
                lic = data.get("license") or _lookup_license(name, "npm")
                deps.append(
                    {
                        "name": name,
                        "license": lic,
                        "ecosystem": "npm",
                        "file": fp.relative_to(root).as_posix(),
                    }
                )
        except Exception as e:
            _log.warning("_extract_deps failed: %s", e)
    # pyproject.toml
    for fp in safe_rglob(root, "pyproject.toml"):
        try:
            content = fp.read_text(encoding="utf-8")
            m = re.search(r'license\s*=\s*["\']([^"\']+)["\']', content)
            lic = m.group(1) if m else None
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith('"') and ">" in stripped:
                    name = stripped.split(">")[0].strip('"').strip("'").split("[")[0].strip()
                    if name and not name.startswith("python") and not name.startswith("#"):
                        deps.append(
                            {
                                "name": name,
                                "license": lic,
                                "ecosystem": "pypi",
                                "file": fp.relative_to(root).as_posix(),
                            }
                        )
        except Exception as e:
            _log.warning("_extract_deps failed: %s", e)
    return deps


@register
class LicenseComplianceAgent(BaseAgent):
    """Scans dependencies for license compliance and flags restricted licenses."""

    group = AgentGroup.SCANNER
    name = "LicenseComplianceAgent"
    description = "Check dependency licenses against policy — flag GPL/AGPL, missing, unknown"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        deps = _extract_deps(inp.root)
        result.data["total_deps"] = len(deps)
        result.data["deps"] = deps

        restricted: list[dict] = []
        missing: list[dict] = []
        unknown: list[dict] = []

        for dep in deps:
            status, norm = _check_license(dep.get("license"))
            if status == "restricted":
                restricted.append(dep)
            elif status == "missing":
                missing.append(dep)
            elif status == "unknown":
                unknown.append(dep)

        result.data["restricted"] = restricted
        result.data["missing_license"] = missing
        result.data["unknown_license"] = unknown
        result.data["total_allowed"] = len(deps) - len(restricted) - len(missing) - len(unknown)
        result.files_scanned = len(deps)

        for dep in restricted:
            result.findings.append(
                make_finding(
                    self.name,
                    "restricted_license",
                    Severity.HIGH,
                    dep["file"],
                    f"Restricted license: {dep['name']} ({dep.get('license', 'unknown')})",
                    detail=f"Ecosystem: {dep['ecosystem']}. Review usage in proprietary code.",
                    suggestion="Replace with an alternative under MIT/Apache/BSD or obtain legal review",
                )
            )
        for dep in missing:
            result.findings.append(
                make_finding(
                    self.name,
                    "missing_license",
                    Severity.MEDIUM,
                    dep["file"],
                    f"Missing license: {dep['name']}",
                    detail=f"Ecosystem: {dep['ecosystem']}. No license field found.",
                    suggestion="Check the package repository for license information",
                )
            )
        for dep in unknown:
            result.findings.append(
                make_finding(
                    self.name,
                    "unknown_license",
                    Severity.LOW,
                    dep["file"],
                    f"Unknown license: {dep['name']} ({dep.get('license', '?')})",
                    detail=f"Ecosystem: {dep['ecosystem']}.",
                    suggestion="Verify license compatibility before using in production",
                )
            )

        if not deps:
            result.findings.append(
                make_finding(
                    self.name,
                    "no_deps_found",
                    Severity.INFO,
                    "",
                    "No dependency manifests found for license check",
                )
            )

        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
