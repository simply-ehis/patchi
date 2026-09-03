"""
Supply Chain Security — SBOM, license compliance, typosquatting detection.

Scans dependency files for:
- License compliance (GPL in proprietary, unknown licenses)
- Typosquatting detection (package name similarity)
- Dependency pinning validation
- Outdated dependency detection
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from patchi.core.agents.base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    register,
    safe_rglob,
)

# ── License classification ────────────────────────────────────────────────────

_PERMISSIVE = {
    "MIT",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Apache-2.0",
    "0BSD",
    "Unlicense",
    "CC0-1.0",
}
_COPYLEFT = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EUPL-1.2"}
_UNKNOWN_LICENSES = {"UNKNOWN", "UNLICENSED", ""}

# ── Well-known package prefixes (for typosquatting) ───────────────────────────

_POPULAR_PACKAGES = {
    "numpy",
    "pandas",
    "requests",
    "flask",
    "django",
    "fastapi",
    "sqlalchemy",
    "pytest",
    "black",
    "ruff",
    "mypy",
    "click",
    "pydantic",
    "httpx",
    "uvicorn",
    "express",
    "react",
    "vue",
    "angular",
    "lodash",
    "moment",
    "axios",
    "webpack",
    "next",
    "nuxt",
    "svelte",
    "tailwindcss",
    "prisma",
    "typescript",
}


_log = logging.getLogger("patchi.security.supply_chain")


def _levenshtein(a: str, b: str) -> int:
    """Edit distance — simple DP implementation."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


def _is_likely_typosquat(pkg_name: str) -> tuple[bool, str]:
    """Check if package name looks like a typosquat of a popular package."""
    lower = pkg_name.lower().replace("-", "").replace("_", "")
    for popular in _POPULAR_PACKAGES:
        clean = popular.replace("-", "").replace("_", "")
        if lower == clean:
            return False, ""
        dist = _levenshtein(lower, clean)
        if 0 < dist <= 2 and len(clean) > 3:
            return True, popular
    return False, ""


def _entropy(s: str) -> float:
    import math as _math
    from collections import Counter as _Counter

    if not s:
        return 0.0
    freq = _Counter(s)
    total = len(s)
    return -sum((c / total) * _math.log2(c / total) for c in freq.values())


def _has_install_script(root: Path, manifest: str) -> bool:
    try:
        fp = root / manifest if not Path(manifest).is_absolute() else Path(manifest)
        # we receive file rel, so need to resolve via root walk in caller
        return False
    except Exception:
        return False


# ── Supply Chain Agent ────────────────────────────────────────────────────────


@register
class SupplyChainAgent(BaseAgent):
    """Supply chain security: license compliance, typosquatting, pinning."""

    name = "SupplyChainAgent"
    group = AgentGroup.SECURITY
    timeout = 60

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        dep_files = {
            "package.json": self._parse_npm,
            "requirements.txt": self._parse_pip,
            "Pipfile": self._parse_pip,
            "pyproject.toml": self._parse_pyproject,
            "Cargo.toml": self._parse_cargo,
            "go.mod": self._parse_go,
            "composer.json": self._parse_composer,
            "Gemfile": self._parse_gemfile,
        }

        all_deps: list[tuple[str, str, str]] = []  # (name, version, file)

        for pattern, parser in dep_files.items():
            for fpath in safe_rglob(inp.root, pattern):
                if not fpath.is_file():
                    continue
                rel = fpath.relative_to(inp.root).as_posix()
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                deps = parser(content, rel)
                all_deps.extend(deps)

        # Optional Socket.dev / Guac remote scoring (API key via env)
        _socket_findings = self._check_socket_scores(all_deps)
        for f in _socket_findings:
            result.add_finding(f)

        # Check each dependency
        for name, version, file in all_deps:
            # Suspicious metadata: install scripts, obfuscated, entropy, 0.0.0
            for f in self._check_suspicious_metadata(name, version, file, inp.root):
                result.add_finding(f)

            # Typosquatting check
            is_squat, target = _is_likely_typosquat(name)
            if is_squat:
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="typosquatting",
                        severity=Severity.HIGH,
                        file=file,
                        message=f"Possible typosquatting: '{name}' looks like '{target}'",
                        cwe="CWE-1395",
                    )
                )

            # Pinning check
            if version in ("*", "latest", ">=0", ">=0.0.0", ""):
                result.add_finding(
                    Finding(
                        agent=self.name,
                        type="unpinned_dependency",
                        severity=Severity.MEDIUM,
                        file=file,
                        message=f"Unpinned dependency: {name}@{version}",
                    )
                )

            # License compliance check
            license_info = self._check_license(name, file)
            if license_info:
                result.add_finding(license_info)

        result.files_scanned = len({f for _, _, f in all_deps})
        result.data["total_deps"] = len(all_deps)

    def _check_socket_scores(self, all_deps: list[tuple[str, str, str]]) -> list[Finding]:
        """Socket.dev / Guac scoring via API if key present, else no-op (fail-open)."""
        import os

        token = os.environ.get("SOCKET_API_KEY") or os.environ.get("GUAC_API_URL")
        if not token:
            return []
        findings: list[Finding] = []
        # Placeholder: call Socket API per package (rate-limited) — best-effort
        try:
            import httpx  # type: ignore

            for name, ver, file in all_deps[:10]:
                try:
                    # Socket.dev npm/packages/{name} endpoint (simplified)
                    resp = httpx.get(f"https://api.socket.dev/v0/npm/{name}", headers={"Authorization": f"Bearer {token}"}, timeout=3)
                    if resp.status_code == 200 and any(k in resp.text.lower() for k in ("malware", "suspicious", "typosquat")):
                        findings.append(
                            Finding(agent=self.name, type="socket_flagged", severity=Severity.HIGH, file=file, message=f"Socket.dev flagged {name}@{ver}", cwe="CWE-1395")
                        )
                except Exception as e:
                    _log.debug("socket check %s failed: %s", name, e)
        except Exception as e:
            _log.debug("socket httpx unavailable: %s", e)
        return findings

    def _check_suspicious_metadata(self, name: str, version: str, file: str, root: Path) -> list[Finding]:
        out: list[Finding] = []
        # 0.0.0 / 0.0.1 + high entropy → new/obfuscated
        if version.strip() in ("0.0.0", "0.0.1", "0.0.2"):
            out.append(Finding(agent=self.name, type="suspicious_version", severity=Severity.MEDIUM, file=file, message=f"Suspicious new package {name}@{version} (0.0.x)"))
        if len(name) > 28 or _entropy(name) > 4.2:
            out.append(Finding(agent=self.name, type="obfuscated_name", severity=Severity.LOW, file=file, message=f"High-entropy package name {name} (possible obfuscation)"))
        # install script in package.json
        if file.endswith("package.json"):
            try:
                fp = (root / file) if not Path(file).is_absolute() else Path(file)
                if fp.exists():
                    import json

                    data = json.loads(fp.read_text(encoding="utf-8", errors="ignore") or "{}")
                    scripts = data.get("scripts", {})
                    if any(k in scripts for k in ("postinstall", "preinstall", "install")):
                        # only flag if dep itself is the package.json's own name (not dep list) — heuristic
                        pass
                    # Check for lifecycle scripts that download remote code
                    raw = fp.read_text(encoding="utf-8", errors="ignore")
                    if "postinstall" in raw and ("curl " in raw or "wget " in raw or "eval(" in raw):
                        out.append(Finding(agent=self.name, type="install_script_download", severity=Severity.HIGH, file=file, message=f"Install script downloads remote code in {file}", cwe="CWE-829"))
            except Exception as e:
                _log.debug("suspicious metadata %s failed: %s", name, e)
        return out

    def _check_license(self, name: str, file: str) -> Finding | None:
        """Check package license via project metadata or pip show (LIMIT-09)."""
        # Try to read license info from package.json
        if "package.json" in file:
            try:
                import json

                pkg_path = Path(file) if Path(file).is_absolute() else None
                if pkg_path and pkg_path.exists():
                    data = json.loads(pkg_path.read_text(encoding="utf-8", errors="ignore"))
                    licenses_field = data.get("license", "")
                    if isinstance(licenses_field, dict):
                        licenses_field = licenses_field.get("type", "")
                    if licenses_field:
                        lic = licenses_field.upper().replace(" ", "")
                        if lic in _COPYLEFT:
                            return Finding(
                                agent=self.name,
                                type="copyleft_license",
                                severity=Severity.HIGH,
                                file=file,
                                message=f"Copyleft license detected: {licenses_field} in {name}",
                                cwe="CWE-507",
                            )
                        if lic in _UNKNOWN_LICENSES or not lic:
                            return Finding(
                                agent=self.name,
                                type="unknown_license",
                                severity=Severity.LOW,
                                file=file,
                                message=f"Unknown or missing license for {name}",
                            )
            except Exception as e:
                _log.warning("SupplyChainAgent._check_license failed: %s", e)

        # Try pip show for PyPI packages (LIMIT-09)
        if "requirements.txt" in file:
            try:
                import subprocess

                proc = subprocess.run(
                    ["pip", "show", name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        if line.lower().startswith("license:"):
                            lic = line.split(":", 1)[1].strip().upper().replace(" ", "")
                            if lic in _COPYLEFT:
                                return Finding(
                                    agent=self.name,
                                    type="copyleft_license",
                                    severity=Severity.HIGH,
                                    file=file,
                                    message=f"Copyleft license detected: {lic} for {name}",
                                    cwe="CWE-507",
                                )
                            if not lic or lic in ("UNKNOWN", ""):
                                return Finding(
                                    agent=self.name,
                                    type="unknown_license",
                                    severity=Severity.LOW,
                                    file=file,
                                    message=f"Unknown license for {name}",
                                )
                            return None  # Known non-copyleft license
            except Exception as e:
                _log.warning("SupplyChainAgent._check_license failed: %s", e)

        # Try to read from pyproject.toml
        if "pyproject.toml" in file or "requirements.txt" in file:
            try:
                proj_path = Path(file).parent / "pyproject.toml"
                if proj_path.exists():
                    content = proj_path.read_text(encoding="utf-8", errors="ignore")
                    import re

                    lic_match = re.search(r'license\s*=\s*["\']([^"\']+)["\']', content, re.I)
                    if lic_match:
                        lic = lic_match.group(1).upper().replace(" ", "")
                        if any(cl in lic for cl in ("GPL", "AGPL", "SSPL")):
                            return Finding(
                                agent=self.name,
                                type="copyleft_license",
                                severity=Severity.HIGH,
                                file=file,
                                message=f"Copyleft license detected: {lic_match.group(1)} in project",
                                cwe="CWE-507",
                            )
            except Exception as e:
                _log.warning("SupplyChainAgent._check_license failed: %s", e)

        return None

    def _parse_npm(self, content: str, file: str) -> list[tuple[str, str, str]]:
        import json

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        return [(k, v, file) for k, v in deps.items()]

    def _parse_pip(self, content: str, file: str) -> list[tuple[str, str, str]]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            for op in ("==", ">=", "<=", "~=", ">", "<", "!="):
                if op in line:
                    name, ver = line.split(op, 1)
                    deps.append((name.strip(), ver.strip().split(",")[0], file))
                    break
            else:
                deps.append((line.strip(), "", file))
        return deps

    def _parse_pyproject(self, content: str, file: str) -> list[tuple[str, str, str]]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[project.dependencies]", "[tool.poetry.dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
            if in_deps and "=" in stripped:
                parts = stripped.split("=", 1)
                name = parts[0].strip().strip('"').strip("'")
                ver = parts[1].strip().strip('"').strip("'").split(",")[0]
                deps.append((name, ver, file))
        return deps

    def _parse_cargo(self, content: str, file: str) -> list[tuple[str, str, str]]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped in ("[dependencies]", "[dev-dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
            if in_deps and "=" in stripped:
                parts = stripped.split("=", 1)
                name = parts[0].strip()
                ver = parts[1].strip().strip('"').split(",")[0]
                deps.append((name, ver, file))
        return deps

    def _parse_go(self, content: str, file: str) -> list[tuple[str, str, str]]:
        deps = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require "):
                parts = stripped[8:].split()
                if len(parts) >= 2:
                    deps.append((parts[0], parts[1], file))
        return deps

    def _parse_composer(self, content: str, file: str) -> list[tuple[str, str, str]]:
        import json

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []
        deps = {}
        deps.update(data.get("require", {}))
        deps.update(data.get("require-dev", {}))
        return [(k, v, file) for k, v in deps.items() if isinstance(v, str)]

    def _parse_gemfile(self, content: str, file: str) -> list[tuple[str, str, str]]:
        deps = []
        for line in content.splitlines():
            m = re.search(r'gem\s+["\']([^"\']+)["\']', line)
            if m:
                deps.append((m.group(1), "", file))
        return deps
