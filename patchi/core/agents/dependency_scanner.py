"""
DependencyScanner — package files, CVE status via OSV API.

Scans dependency files including:
- package.json (npm/yarn)
- requirements.txt (pip)
- Pipfile (pipenv)
- poetry.lock (Poetry)
- Cargo.toml (Cargo/Rust)
- go.mod (Go modules)
- composer.json (Composer/PHP)
- Gemfile (Bundler/Ruby)

Checks versions against OSV (Open Source Vulnerability) database
for known CVEs and security issues.

Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from pathlib import Path

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS
from patchi.core.constants import is_offline

from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    AgentStatus,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

# Keep a direct alias to the original make_finding to avoid accidental
# recursive replacement when updating calls to use the compatibility wrapper.
_base_make_finding = make_finding


_log = logging.getLogger("patchi.agents.dependency_scanner")


@register
class DependencyScanner(BaseAgent):
    """Scanner for project dependencies and CVEs."""

    group = AgentGroup.SCANNER
    name = "DependencyScanner"
    description = "Dependency files, CVE status via OSV API"

    def _mkf(self, *args, **kwargs) -> Finding:
        """Compatibility wrapper for legacy make_finding calls in this scanner."""
        # Old positional style: (Severity, file, line_start, title, description, evidence)
        if args and isinstance(args[0], Severity):
            severity = args[0]
            file = args[1] if len(args) > 1 else ""
            line = args[2] if len(args) > 2 else 0
            title = args[3] if len(args) > 3 else ""
            message = args[4] if len(args) > 4 else ""
            evidence = args[5] if len(args) > 5 else ""
            finding_type = kwargs.pop("finding_type", None) or title.lower().replace(
                " ", "_"
            ).replace(":", "").replace("'", "").replace("-", "_")
            return _base_make_finding(
                self.name,
                finding_type,
                severity,
                file,
                message,
                line=line,
                evidence=evidence,
                **kwargs,
            )

        # Keyword style: severity=..., file=..., title=..., description=..., evidence=...
        if "severity" in kwargs and ("file" in kwargs or "file_path" in kwargs):
            severity = kwargs.pop("severity")
            file = kwargs.pop("file", kwargs.pop("file_path", ""))
            line = kwargs.pop("line_start", kwargs.pop("line", 0))
            title = kwargs.pop("title", "")
            message = kwargs.pop("description", title)
            evidence = kwargs.pop("evidence", "")
            finding_type = kwargs.pop("finding_type", None) or title.lower().replace(
                " ", "_"
            ).replace(":", "").replace("'", "").replace("-", "_")
            return _base_make_finding(
                self.name,
                finding_type,
                severity,
                file,
                message,
                line=line,
                evidence=evidence,
                **kwargs,
            )

        return _base_make_finding(*args, **kwargs)

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan dependency files for vulnerabilities.

        Populates `result.data['dependencies']` and `result.data['total_deps']`.
        """
        findings: list[Finding] = []
        dependencies: dict[str, str] = {}
        vulns_count = 0

        # Define dependency file patterns
        dep_files = [
            "package.json",
            "requirements.txt",
            "Pipfile",
            "poetry.lock",
            "Cargo.toml",
            "Cargo.lock",
            "go.mod",
            "go.sum",
            "composer.json",
            "Gemfile",
            "Gemfile.lock",
            "yarn.lock",
            "pnpm-lock.yaml",
        ]

        # Search for dependency files and build dependency map
        found_any = False
        for dep_file in dep_files:
            for file_path in safe_rglob(inp.root, dep_file):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        found_any = True
                        file_findings = self._scan_dep_file(file_path, rel_path)
                        findings.extend(file_findings)

                        # Lightweight parsing to populate dependencies dict for tests
                        try:
                            content = file_path.read_text(encoding="utf-8")
                            if file_path.name == "package.json":
                                data = json.loads(content)
                                deps = data.get("dependencies", {})
                                dev_deps = data.get("devDependencies", {})
                                for n, v in {**deps, **dev_deps}.items():
                                    dependencies[n] = v
                            elif file_path.name == "requirements.txt":
                                for line in content.splitlines():
                                    ln = line.strip()
                                    if not ln or ln.startswith("#"):
                                        continue
                                    pkg_name = ln
                                    version = "unknown"
                                    for sep in ["==", ">=", "<=", ">", "<"]:
                                        if sep in ln:
                                            pkg_name, version = ln.split(sep, 1)
                                            break
                                    dependencies[pkg_name.strip()] = version.strip()
                        except Exception as e:
                            _log.warning("DependencyScanner._run failed: %s", e)

        # If no dependency files were found, emit an informational finding
        if not found_any:
            result.add_finding(
                self._mkf(
                    severity=Severity.INFO,
                    file="",
                    line_start=0,
                    title="No dependency files found",
                    description="Project contains no recognized dependency files",
                    finding_type="no_dependency_file",
                    evidence="",
                )
            )

        # Aggregate dependencies and vulnerability counts from findings
        for f in findings:
            # Titles created by legacy code use formats like "Dependency: name@version" or "VULNERABILITY: name@version"
            getattr(f, "message", "") or getattr(f, "type", "") or ""
            # Prefer finding.type if it encodes vulnerability info
            if f.message.startswith("VULNERABILITY:") or f.type.startswith("vulnerability"):
                vulns_count += 1
            if f.message.startswith("Dependency:"):
                # message may be like "Dependency: name@version" if compat preserved
                dep_text = f.message[len("Dependency:") :].strip()
                if "@" in dep_text:
                    name, version = dep_text.split("@", 1)
                else:
                    name, version = dep_text, "unknown"
                dependencies[name.strip()] = version.strip()

        # Add findings to result
        for f in findings:
            result.add_finding(f)

        result.data["dependencies"] = dependencies
        result.data["total_deps"] = len(dependencies)
        result.data["vulnerable_deps"] = vulns_count
        result.files_scanned = sum(1 for _ in safe_rglob(inp.root, "*"))
        result.data["needs_ai"] = False
        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
        # Skip ignored directories (node_modules, .venv, etc.)
        from pathlib import PurePosixPath

        if any(p in DEFAULT_IGNORE_DIRS for p in PurePosixPath(file_path).parts):
            return True

        from pathlib import PurePosixPath

        # Check restrictions
        restrictions = inp.config.get("restrictions", [])
        for r in restrictions:
            if r.get("enabled", True):
                path = r["path"]
                if file_path.startswith(path) or PurePosixPath(file_path).match(path):
                    if r["type"] == "NO_TOUCH":
                        return True
                    elif r["type"] == "SCAN_ONLY" and self.__class__.__name__ == "FixAgent":
                        return True
        return False

    def _scan_dep_file(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a dependency file."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            if file_path.name == "package.json":
                findings.extend(self._scan_package_json(file_path, rel_path, content))
            elif file_path.name == "requirements.txt":
                findings.extend(self._scan_requirements_txt(file_path, rel_path, content))
            elif file_path.name == "Pipfile":
                findings.extend(self._scan_pipfile(file_path, rel_path, content))
            elif file_path.name == "poetry.lock":
                findings.extend(self._scan_poetry_lock(file_path, rel_path, content))
            elif file_path.name in ["Cargo.toml", "Cargo.lock"]:
                findings.extend(self._scan_cargo_file(file_path, rel_path, content))
            elif file_path.name == "go.mod":
                findings.extend(self._scan_go_mod(file_path, rel_path, content))
            elif file_path.name == "composer.json":
                findings.extend(self._scan_composer_json(file_path, rel_path, content))
            elif file_path.name in ["Gemfile", "Gemfile.lock"]:
                findings.extend(self._scan_gemfile(file_path, rel_path, content))
            elif file_path.name in ["yarn.lock", "pnpm-lock.yaml"]:
                findings.extend(self._scan_lock_file(file_path, rel_path, content))

            findings.append(
                self._mkf(
                    severity=Severity.INFO,
                    file=rel_path,
                    line_start=0,
                    title=f"Dependency File: {file_path.name}",
                    description="Found dependency file with vulnerability checking",
                    evidence=f"File: {file_path.name}",
                )
            )

        except Exception as e:
            findings.append(
                self._mkf(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Dependency file read error",
                    description=f"Could not read dependency file {file_path.name}: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_package_json(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan package.json for dependencies and vulnerabilities."""
        findings = []

        try:
            data = json.loads(content)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})

            # Combine all dependencies
            all_deps = {}
            all_deps.update(dict(deps.items()))
            all_deps.update(dict(dev_deps.items()))

            for name, version in all_deps.items():
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=0,
                        title=f"Dependency: {name}@{version}",
                        description="JavaScript dependency",
                        evidence=f"Version: {version}",
                    )
                )

                # Check for vulnerabilities via OSV API
                vulns = self._check_npm_vulnerabilities(name, version)
                for vuln in vulns:
                    severity = self._map_osv_severity(
                        vuln.get("severity", [{}])[0].get("score", "UNKNOWN")
                    )
                    findings.append(
                        self._mkf(
                            severity=severity,
                            file=rel_path,
                            line_start=0,
                            title=f"VULNERABILITY: {name}@{version}",
                            description=vuln.get("summary", "Unknown vulnerability"),
                            evidence=json.dumps(vuln),
                        )
                    )

        except json.JSONDecodeError as e:
            findings.append(
                self._mkf(
                    severity=Severity.HIGH,
                    file=rel_path,
                    line_start=e.lineno,
                    title="Invalid package.json",
                    description=f"JSON syntax error: {str(e)}",
                    evidence=e.msg,
                )
            )

        return findings

    def _scan_requirements_txt(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan requirements.txt for dependencies."""
        findings = []

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                # Extract package name and version
                if "==" in line:
                    pkg_name, version = line.split("==", 1)
                elif ">=" in line:
                    pkg_name, version = line.split(">=", 1)
                elif "<=" in line:
                    pkg_name, version = line.split("<=", 1)
                elif ">" in line:
                    pkg_name, version = line.split(">", 1)
                elif "<" in line:
                    pkg_name, version = line.split("<", 1)
                else:
                    pkg_name, version = line, "unknown"

                pkg_name = pkg_name.strip()
                version = version.strip()

                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=i,
                        title=f"Dependency: {pkg_name}@{version}",
                        description="Python dependency",
                        evidence=line,
                    )
                )

                # Check for vulnerabilities via OSV API
                vulns = self._check_pypi_vulnerabilities(pkg_name, version)
                for vuln in vulns:
                    severity = self._map_osv_severity(
                        vuln.get("severity", [{}])[0].get("score", "UNKNOWN")
                    )
                    findings.append(
                        self._mkf(
                            severity=severity,
                            file=rel_path,
                            line_start=i,
                            title=f"VULNERABILITY: {pkg_name}@{version}",
                            description=vuln.get("summary", "Unknown vulnerability"),
                            evidence=json.dumps(vuln),
                        )
                    )

        return findings

    def _scan_pipfile(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan Pipfile for dependencies."""
        findings = []

        # Pipfiles are TOML format, but Python < 3.11 doesn't have built-in TOML support
        # So we'll use regex for basic parsing
        lines = content.splitlines()
        current_section = ""

        for i, line in enumerate(lines, 1):
            line = line.strip()

            # Identify section
            if line.startswith("["):
                current_section = line.strip("[]").strip()
                continue

            # Look for package declarations in the right sections
            if current_section in ["packages", "dev-packages"]:
                pkg_match = re.match(r"^(\w[-\w]*)\s*=\s*", line)
                if pkg_match:
                    pkg_name = pkg_match.group(1)
                    # Extract version from the rest of the line
                    version_part = line[len(pkg_name) :].strip("= ").strip('"')
                    findings.append(
                        self._mkf(
                            severity=Severity.INFO,
                            file=rel_path,
                            line_start=i,
                            title=f"Dependency: {pkg_name}@{version_part}",
                            description="Python dependency from Pipfile",
                            evidence=line,
                        )
                    )

        return findings

    def _scan_poetry_lock(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan poetry.lock for dependencies."""
        findings = []

        # Poetry lock files are TOML format
        lines = content.splitlines()
        current_package = {}

        for i, line in enumerate(lines, 1):
            line = line.strip()

            # Look for package entries
            if line.startswith("[[package]]"):
                # Process previous package if exists
                if current_package:
                    pkg_name = current_package.get("name", "unknown")
                    version = current_package.get("version", "unknown")
                    findings.append(
                        self._mkf(
                            severity=Severity.INFO,
                            file=rel_path,
                            line_start=i,
                            title=f"Dependency: {pkg_name}@{version}",
                            description="Python dependency from Poetry lock",
                            evidence=f"{pkg_name}=={version}",
                        )
                    )

                current_package = {}
            elif "=" in line and current_package is not None:
                # Parse key=value pairs
                key, value = line.split("=", 1)
                key = key.strip().strip('"')
                value = value.strip().strip('"')
                current_package[key] = value

        # Process the last package
        if current_package:
            pkg_name = current_package.get("name", "unknown")
            version = current_package.get("version", "unknown")
            findings.append(
                self._mkf(
                    severity=Severity.INFO,
                    file=rel_path,
                    line_start=len(lines),
                    title=f"Dependency: {pkg_name}@{version}",
                    description="Python dependency from Poetry lock",
                    evidence=f"{pkg_name}=={version}",
                )
            )

        return findings

    def _scan_cargo_file(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan Cargo.toml or Cargo.lock for dependencies."""
        findings = []

        lines = content.splitlines()
        in_deps_section = False

        for i, line in enumerate(lines, 1):
            line = line.strip()

            # Identify dependencies section
            if line.startswith("[dependencies]") or line.startswith("[dev-dependencies]"):
                in_deps_section = True
                continue
            elif line.startswith("[") and in_deps_section:
                in_deps_section = False

            # Look for package declarations in dependencies section
            if in_deps_section and "=" in line:
                pkg_match = re.match(r"^(\w[\w\-_]*)\s*=", line)
                if pkg_match:
                    pkg_name = pkg_match.group(1)
                    # Extract version from the rest of the line
                    version_part = line[len(pkg_name) :].strip("= ").strip('"')
                    findings.append(
                        self._mkf(
                            severity=Severity.INFO,
                            file=rel_path,
                            line_start=i,
                            title=f"Dependency: {pkg_name}@{version_part}",
                            description="Rust dependency",
                            evidence=line,
                        )
                    )

        return findings

    def _scan_go_mod(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan go.mod for dependencies."""
        findings = []

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line = line.strip()

            # Look for require statements
            if line.startswith("require "):
                # Extract package and version
                req_parts = line[8:].strip().split()  # Remove "require " prefix
                if len(req_parts) >= 2:
                    pkg_name = req_parts[0]
                    version = req_parts[1]
                    findings.append(
                        self._mkf(
                            severity=Severity.INFO,
                            file=rel_path,
                            line_start=i,
                            title=f"Dependency: {pkg_name}@{version}",
                            description="Go dependency",
                            evidence=line,
                        )
                    )

        return findings

    def _scan_composer_json(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan composer.json for PHP dependencies."""
        findings = []

        try:
            data = json.loads(content)
            deps = data.get("require", {})
            dev_deps = data.get("require-dev", {})

            # Combine all dependencies
            all_deps = {}
            all_deps.update(dict(deps.items()))
            all_deps.update(dict(dev_deps.items()))

            for name, version in all_deps.items():
                findings.append(
                    self._mkf(
                        severity=Severity.INFO,
                        file=rel_path,
                        line_start=0,
                        title=f"Dependency: {name}@{version}",
                        description="PHP dependency",
                        evidence=f"Version: {version}",
                    )
                )

        except json.JSONDecodeError as e:
            findings.append(
                self._mkf(
                    severity=Severity.HIGH,
                    file=rel_path,
                    line_start=e.lineno,
                    title="Invalid composer.json",
                    description=f"JSON syntax error: {str(e)}",
                    evidence=e.msg,
                )
            )

        return findings

    def _scan_gemfile(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan Gemfile or Gemfile.lock for Ruby dependencies."""
        findings = []

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line = line.strip()

            # Look for gem statements
            if "gem " in line and not line.startswith("#"):
                # Extract gem name
                gem_match = re.search(r'gem\s+["\']([^"\']+)["\']', line)
                if gem_match:
                    gem_name = gem_match.group(1)
                    findings.append(
                        self._mkf(
                            severity=Severity.INFO,
                            file=rel_path,
                            line_start=i,
                            title=f"Dependency: {gem_name}",
                            description="Ruby dependency",
                            evidence=line,
                        )
                    )

        return findings

    def _scan_lock_file(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Scan lock files (yarn.lock, pnpm-lock.yaml) for dependencies."""
        findings = []

        lines = content.splitlines()

        # Different parsing for different lock file types
        if file_path.name == "yarn.lock":
            # Yarn lock files have "package@version" entries
            for i, line in enumerate(lines, 1):
                if line.strip().endswith(":") and "@" in line:
                    # Extract package and version
                    pkg_part = line.strip().rstrip(":")
                    if "@" in pkg_part:
                        pkg_name = pkg_part.split("@")[0]
                        findings.append(
                            self._mkf(
                                severity=Severity.INFO,
                                file=rel_path,
                                line_start=i,
                                title=f"Dependency: {pkg_name}",
                                description="JavaScript dependency from lock file",
                                evidence=pkg_part,
                            )
                        )
        elif file_path.name == "pnpm-lock.yaml":
            # PNPM lock files have similar format to yarn
            for i, line in enumerate(lines, 1):
                if line.strip().endswith(":") and "/" in line:
                    # Extract package name
                    pkg_part = line.strip().rstrip(":")
                    if "/" in pkg_part and "@" in pkg_part:
                        pkg_name = pkg_part.split("/")[-1].split("@")[0]
                        findings.append(
                            self._mkf(
                                severity=Severity.INFO,
                                file=rel_path,
                                line_start=i,
                                title=f"Dependency: {pkg_name}",
                                description="JavaScript dependency from pnpm lock",
                                evidence=pkg_part,
                            )
                        )

        return findings

    def _check_npm_vulnerabilities(self, package_name: str, version: str) -> list[dict]:
        """Check npm package for vulnerabilities via OSV API."""
        if is_offline():
            return []
        try:
            url = "https://api.osv.dev/v1/query"
            query = {"package": {"name": package_name, "ecosystem": "npm"}, "version": version}

            req = urllib.request.Request(
                url,
                data=json.dumps(query).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            response = urllib.request.urlopen(req, timeout=15)
            data = json.loads(response.read().decode("utf-8"))

            return data.get("vulns", [])
        except Exception as e:
            # Return empty list if API call fails
            _log.warning("DependencyScanner._check_npm_vulnerabilities failed: %s", e)
            return []

    def _check_pypi_vulnerabilities(self, package_name: str, version: str) -> list[dict]:
        """Check PyPI package for vulnerabilities via OSV API."""
        if is_offline():
            return []
        try:
            url = "https://api.osv.dev/v1/query"
            query = {"package": {"name": package_name, "ecosystem": "PyPI"}, "version": version}

            req = urllib.request.Request(
                url,
                data=json.dumps(query).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            response = urllib.request.urlopen(req, timeout=15)
            data = json.loads(response.read().decode("utf-8"))

            return data.get("vulns", [])
        except Exception as e:
            # Return empty list if API call fails
            _log.warning("DependencyScanner._check_pypi_vulnerabilities failed: %s", e)
            return []

    def _map_osv_severity(self, osv_severity: str) -> Severity:
        """Map OSV severity to our severity levels."""
        if not osv_severity or osv_severity == "UNKNOWN":
            return Severity.LOW

        # Convert to uppercase for comparison
        sev = osv_severity.upper()

        if sev in ["CRITICAL", "HIGH"]:
            return Severity.CRITICAL
        elif sev == "MEDIUM":
            return Severity.MEDIUM
        else:
            return Severity.LOW
