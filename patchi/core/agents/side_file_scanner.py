"""
SideFileScanner — configs, .env vars, CI/CD structure.

Scans non-source files including:
- Configuration files (json, yaml, toml, xml)
- Environment files (.env, .env.local, etc.)
- Build files (package.json, requirements.txt, Cargo.toml, etc.)
- CI/CD files (github workflows, gitlab ci, etc.)
- Script files (bash, sh, ps1, etc.)

Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import yaml

from patchi.core.brain.languages import DEFAULT_IGNORE_DIRS

from .base import (
    AgentGroup,
    AgentInput,
    AgentResult,
    BaseAgent,
    Finding,
    Severity,
    make_finding,
    register,
    safe_rglob,
)

_log = logging.getLogger("patchi.agents.side_file_scanner")


@register
class SideFileScanner(BaseAgent):
    """Scanner for configuration and side files."""

    group = AgentGroup.SCANNER
    name = "SideFileScanner"
    description = "Config files, environment files, build files, CI/CD, scripts"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Scan side files for configuration and structure.

        Populates `result.data['config_map']`, `result.data['env_vars']`, and
        `result.data['cicd_structure']` in addition to findings.
        """
        findings = []
        config_map: dict = {}
        env_vars: list[str] = []
        cicd_structure: dict = {}
        # Define file patterns to look for
        config_patterns = [
            "*.json",
            "*.yml",
            "*.yaml",
            "*.toml",
            "*.xml",
            "*.ini",
            "*.cfg",
            "*.conf",
            ".env*",
            "*rc",
            ".gitignore",
            ".dockerignore",
            "Dockerfile*",
            "Makefile*",
            "package.json",
            "requirements.txt",
            "Cargo.toml",
            "go.mod",
            "composer.json",
            "Gemfile",
            "Pipfile",
            "poetry.lock",
            "yarn.lock",
            "pnpm-lock.yaml",
        ]

        # CI/CD patterns
        ci_cd_patterns = [
            ".github/workflows/*",
            ".gitlab-ci.yml",
            ".travis.yml",
            "azure-pipelines.yml",
            ".circleci/*",
            ".drone.yml",
            "Jenkinsfile",
            ".woodpecker.yml",
        ]

        # Script patterns
        script_patterns = ["*.sh", "*.bash", "*.ps1", "*.bat", "*.cmd", "*.zsh"]

        # Search for config files
        for pattern in config_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_config_file(file_path, rel_path))
                        # Populate config_map summary for tests
                        config_map[rel_path] = {"name": file_path.name}

        # Search for CI/CD files
        for pattern in ci_cd_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_ci_cd_file(file_path, rel_path))
                        # add to cicd_structure
                        parent = (
                            ".github/workflows"
                            if ".github/workflows" in rel_path
                            else file_path.parent.relative_to(inp.root).as_posix()
                        )
                        cicd_structure.setdefault(parent, []).append(rel_path)

        # Search for script files
        for pattern in script_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        findings.extend(self._scan_script_file(file_path, rel_path))

        # If an explicit .env file exists, extract env var names
        env_path = inp.root / ".env"
        if env_path.exists():
            try:
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    m = re.match(r"^([A-Z_][A-Z0-9_]*)=", line)
                    if m:
                        env_vars.append(m.group(1))
            except Exception as e:
                _log.warning("SideFileScanner._run failed: %s", e)
        # Fill result
        for f in findings:
            result.add_finding(f)

        result.data["config_map"] = config_map
        result.data["env_vars"] = env_vars
        result.data["cicd_structure"] = cicd_structure
        result.files_scanned = len(config_map) + len(cicd_structure)
        result.data["file_types"] = ["config", "env", "ci_cd", "script"]
        result.data["needs_ai"] = False

    _SKIP_DIRS = DEFAULT_IGNORE_DIRS

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on ignore dirs and restrictions."""
        from pathlib import PurePosixPath

        # Skip ignored directories (node_modules, .venv, etc.)
        parts = PurePosixPath(file_path).parts
        if any(p in self._SKIP_DIRS for p in parts):
            return True

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

    def _scan_config_file(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan configuration files."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            # Determine file type and parse accordingly
            if file_path.suffix.lower() in [".json"]:
                findings.extend(self._parse_json_config(file_path, rel_path, content))
            elif file_path.suffix.lower() in [".yml", ".yaml"]:
                findings.extend(self._parse_yaml_config(file_path, rel_path, content))
            elif file_path.name in ["package.json"]:
                findings.extend(self._parse_package_json(file_path, rel_path, content))
            elif file_path.name in ["requirements.txt"]:
                findings.extend(self._parse_requirements_txt(file_path, rel_path, content))
            elif file_path.suffix.lower() in [".toml"]:
                findings.extend(self._parse_toml_config(file_path, rel_path, content))

            # Check for environment variables in config
            findings.extend(self._find_env_vars_in_content(file_path, rel_path, content))

        except Exception as e:
            findings.append(
                make_finding(
                    self.name,
                    "config_read_error",
                    Severity.LOW,
                    rel_path,
                    f"Could not read config file {file_path.name}: {str(e)}",
                    line=0,
                    evidence=str(e),
                )
            )

        return findings

    def _parse_json_config(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Parse JSON configuration files."""
        findings = []
        try:
            data = json.loads(content)

            findings.append(
                make_finding(
                    self.name,
                    "json_config",
                    Severity.INFO,
                    rel_path,
                    f"Found JSON config with {len(data)} top-level keys",
                    line=0,
                    evidence=str(list(data.keys())),
                )
            )
        except json.JSONDecodeError as e:
            findings.append(
                make_finding(
                    self.name,
                    "invalid_json",
                    Severity.HIGH,
                    rel_path,
                    f"JSON syntax error: {str(e)}",
                    line=e.lineno,
                    evidence=e.msg,
                )
            )

        return findings

    def _parse_yaml_config(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Parse YAML configuration files."""
        findings = []
        try:
            data = yaml.safe_load(content)

            if isinstance(data, dict):
                findings.append(
                    make_finding(
                        self.name,
                        "yaml_config",
                        Severity.INFO,
                        rel_path,
                        f"Found YAML config with {len(data)} top-level keys",
                        line=0,
                        evidence=str(list(data.keys())),
                    )
                )
            elif isinstance(data, list):
                findings.append(
                    make_finding(
                        self.name,
                        "yaml_config",
                        Severity.INFO,
                        rel_path,
                        f"Found YAML config with {len(data)} items",
                        line=0,
                        evidence=f"List with {len(data)} items",
                    )
                )
        except yaml.YAMLError as e:
            findings.append(
                make_finding(
                    self.name,
                    "invalid_yaml",
                    Severity.HIGH,
                    rel_path,
                    f"YAML syntax error: {str(e)}",
                    line=0,
                    evidence=str(e),
                )
            )

        return findings

    def _parse_package_json(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Parse package.json file."""
        findings = []
        try:
            data = json.loads(content)

            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})

            findings.append(
                make_finding(
                    self.name,
                    "package_json",
                    Severity.INFO,
                    rel_path,
                    f"Dependencies: {len(deps)}, Dev Dependencies: {len(dev_deps)}",
                    line=0,
                    evidence=f"Deps: {list(deps.keys())}, DevDeps: {list(dev_deps.keys())}",
                )
            )

            # Check for security-related fields
            if "scripts" in data:
                for script_name, script_content in data["scripts"].items():
                    if any(security_cmd in script_content.lower() for security_cmd in ["audit", "security"]):
                        findings.append(
                            make_finding(
                                self.name,
                                "security_script",
                                Severity.INFO,
                                rel_path,
                                f"Script '{script_name}' contains security-related commands",
                                line=0,
                                evidence=script_content,
                            )
                        )

        except json.JSONDecodeError as e:
            findings.append(
                make_finding(
                    self.name,
                    "invalid_package_json",
                    Severity.HIGH,
                    rel_path,
                    f"JSON syntax error in package.json: {str(e)}",
                    line=e.lineno,
                    evidence=e.msg,
                )
            )

        return findings

    def _parse_requirements_txt(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Parse requirements.txt file."""
        findings = []

        lines = content.splitlines()
        dep_count = 0
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                dep_count += 1
                findings.append(
                    make_finding(
                        self.name,
                        "requirement",
                        Severity.INFO,
                        rel_path,
                        line,
                        line=i,
                        evidence=line,
                    )
                )

        findings.append(
            make_finding(
                self.name,
                "requirements",
                Severity.INFO,
                rel_path,
                f"Found {dep_count} requirements",
                line=0,
                evidence=f"Total: {dep_count} packages",
            )
        )

        return findings

    def _parse_toml_config(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Parse TOML configuration files."""
        findings = []

        # Since Python < 3.11 doesn't have built-in TOML support, we'll just do basic parsing
        lines = content.splitlines()
        findings.append(
            make_finding(
                self.name,
                "toml_config",
                Severity.INFO,
                rel_path,
                f"Found TOML config with {len(lines)} lines",
                line=0,
                evidence=f"First few lines: {'; '.join(lines[:5])}",
            )
        )

        # Look for common TOML patterns
        for i, line in enumerate(lines, 1):
            if line.strip().startswith("["):  # TOML table
                findings.append(
                    make_finding(
                        self.name,
                        "toml_table",
                        Severity.INFO,
                        rel_path,
                        line.strip(),
                        line=i,
                        evidence=line.strip(),
                    )
                )

        return findings

    def _scan_ci_cd_file(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan CI/CD configuration files."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            findings.append(
                make_finding(
                    self.name,
                    "ci_cd_config",
                    Severity.INFO,
                    rel_path,
                    f"Found CI/CD config file: {file_path.name}",
                    line=0,
                    evidence=f"File: {file_path.name}",
                )
            )

            # Look for common CI/CD patterns
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                if any(keyword in line.lower() for keyword in ["deploy", "publish", "release", "build"]):
                    findings.append(
                        make_finding(
                            self.name,
                            "ci_cd_step",
                            Severity.INFO,
                            rel_path,
                            line.strip(),
                            line=i,
                            evidence=line.strip(),
                        )
                    )
        except Exception as e:
            findings.append(
                make_finding(
                    self.name,
                    "ci_cd_read_error",
                    Severity.LOW,
                    rel_path,
                    f"Could not read CI/CD file {file_path.name}: {str(e)}",
                    line=0,
                    evidence=str(e),
                )
            )

        return findings

    def _scan_script_file(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan script files."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            findings.append(
                make_finding(
                    self.name,
                    "script_file",
                    Severity.INFO,
                    rel_path,
                    f"Found script file: {file_path.name}",
                    line=0,
                    evidence=f"File: {file_path.name}",
                )
            )

            # Look for potentially risky commands
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                if any(risky_cmd in line.lower() for risky_cmd in ["rm -rf", "sudo", "chmod", "chown", "mv /", "cp /"]):
                    findings.append(
                        make_finding(
                            self.name,
                            "risky_command",
                            Severity.MEDIUM,
                            rel_path,
                            line.strip(),
                            line=i,
                            evidence=line.strip(),
                        )
                    )
        except Exception as e:
            findings.append(
                make_finding(
                    self.name,
                    "script_read_error",
                    Severity.LOW,
                    rel_path,
                    f"Could not read script file {file_path.name}: {str(e)}",
                    line=0,
                    evidence=str(e),
                )
            )

        return findings

    def _find_env_vars_in_content(self, file_path: Path, rel_path: str, content: str) -> list[Finding]:
        """Find environment variable references in content."""
        findings = []

        # Look for common environment variable patterns
        env_var_pattern = r"\$\{\w+\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%"
        matches = re.finditer(env_var_pattern, content)

        for match in matches:
            line_start = content[: match.start()].count("\n") + 1
            findings.append(
                make_finding(
                    self.name,
                    "env_reference",
                    Severity.INFO,
                    rel_path,
                    match.group(),
                    line=line_start,
                    evidence=match.group(),
                )
            )

        return findings
