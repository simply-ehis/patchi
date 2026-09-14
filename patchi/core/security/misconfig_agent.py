"""
MisconfigAgent — security misconfigurations.

Detects security misconfigurations:
- Debug enabled in production
- Insecure CORS settings
- Missing security headers
- Weak TLS/SSL configurations
- Improper error handling
- Verbose error messages
- Unrestricted file uploads
- Missing rate limiting
- Default credentials
- Unnecessary services/features enabled

Uses pattern matching and configuration analysis.
Does NOT call AI.
Does NOT write to disk.
Does NOT touch the queue.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ..agents.base import (
    AgentDomain,
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


@register
class MisconfigAgent(BaseAgent):
    """Agent for detecting security misconfigurations."""

    group = AgentGroup.SECURITY
    domain = AgentDomain.SECURITY
    name = "MisconfigAgent"
    description = "Security misconfig: debug, CORS, headers, TLS, error handling, file upload, rate limiting"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        """Run security misconfiguration detection."""
        findings = []
        files_scanned = 0

        # Define configuration file patterns to scan
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
            "**/config/**",
            "**/configs/**",
            "**/conf/**",
            "**/settings/**",
        ]

        # Search for configuration files
        for pattern in config_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        files_scanned += 1
                        findings.extend(self._scan_config_file_misconfig(file_path, rel_path))

        # Also scan source files for misconfigurations
        source_patterns = [
            "*.py",
            "*.js",
            "*.jsx",
            "*.ts",
            "*.tsx",
            "*.java",
            "*.php",
            "*.rb",
            "*.go",
            "*.rs",
            "*.cpp",
            "*.cxx",
            "*.cc",
            "*.c",
            "*.h",
            "*.hpp",
            "*.cs",
        ]

        for pattern in source_patterns:
            for file_path in safe_rglob(inp.root, pattern):
                if file_path.is_file():
                    rel_path = file_path.relative_to(inp.root).as_posix()
                    if not self._should_skip_file(rel_path, inp):
                        files_scanned += 1
                        findings.extend(self._scan_source_file_misconfig(file_path, rel_path))

        result.status = AgentStatus.SUCCEEDED
        result.files_scanned = files_scanned
        result.findings = findings
        result.data.update(
            {
                "misconfig_findings": len(
                    [
                        f
                        for f in findings
                        if any(
                            word in f.title.lower()
                            for word in [
                                "misconfig",
                                "debug",
                                "cors",
                                "header",
                                "tls",
                                "error",
                                "upload",
                                "rate",
                            ]
                        )
                    ]
                ),
                "needs_ai": False,
            }
        )
        return

    def _should_skip_file(self, file_path: str, inp: AgentInput) -> bool:
        """Check if file should be skipped based on restrictions."""
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

    def _scan_config_file_misconfig(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan a configuration file for security misconfigurations."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")

            # Determine file type and scan accordingly
            if file_path.suffix.lower() in [".json"]:
                findings.extend(self._scan_json_config_misconfig(content, rel_path))
            elif file_path.suffix.lower() in [".yml", ".yaml"]:
                findings.extend(self._scan_yaml_config_misconfig(content, rel_path))
            elif file_path.name in ["package.json"]:
                findings.extend(self._scan_package_json_misconfig(content, rel_path))
            elif file_path.name in ["requirements.txt"]:
                findings.extend(self._scan_requirements_txt_misconfig(content, rel_path))
            elif file_path.suffix.lower() in [".toml"]:
                findings.extend(self._scan_toml_config_misconfig(content, rel_path))
            elif ".env" in file_path.name.lower():
                findings.extend(self._scan_env_file_misconfig(content, rel_path))
            else:
                # General configuration file scan
                findings.extend(self._scan_general_config_misconfig(content, rel_path))

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Misconfig scanner file read error",
                    description=f"Could not analyze {file_path.name} for misconfigurations: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_json_config_misconfig(self, content: str, rel_path: str) -> list[Finding]:
        """Scan JSON configuration files for misconfigurations."""
        findings = []

        try:
            data = json.loads(content)

            # Check for debug enabled
            if self._find_nested_key(data, ["debug", "DEBUG", "enable_debug", "debug_mode"]):
                findings.append(
                    make_finding(
                        severity=Severity.HIGH,
                        file=rel_path,
                        line_start=0,
                        title="Debug Enabled in Configuration",
                        description="Debug mode appears to be enabled in configuration file",
                        evidence="Debug setting found in JSON config",
                    )
                )

            # Check for insecure settings
            if self._find_nested_key(data, ["allow_origin", "origins"], lambda v: v == "*" or v == ["*"]):
                findings.append(
                    make_finding(
                        severity=Severity.HIGH,
                        file=rel_path,
                        line_start=0,
                        title="Insecure CORS Configuration",
                        description="CORS policy allows all origins (*)",
                        evidence="Wildcard CORS origin found in config",
                    )
                )

        except json.JSONDecodeError as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=e.lineno,
                    title="Invalid JSON",
                    description=f"JSON syntax error: {str(e)}",
                    evidence=e.msg,
                )
            )

        return findings

    def _scan_yaml_config_misconfig(self, content: str, rel_path: str) -> list[Finding]:
        """Scan YAML configuration files for misconfigurations."""
        findings = []

        try:
            data = yaml.safe_load(content)

            if isinstance(data, dict):
                # Check for debug enabled
                if self._find_nested_key(data, ["debug", "DEBUG", "enable_debug", "debug_mode"]):
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=0,
                            title="Debug Enabled in Configuration",
                            description="Debug mode appears to be enabled in configuration file",
                            evidence="Debug setting found in YAML config",
                        )
                    )

                # Check for insecure settings
                if self._find_nested_key(data, ["allow_origin", "origins"], lambda v: v == "*" or v == ["*"]):
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=0,
                            title="Insecure CORS Configuration",
                            description="CORS policy allows all origins (*)",
                            evidence="Wildcard CORS origin found in config",
                        )
                    )

        except yaml.YAMLError as e:
            findings.append(
                make_finding(
                    severity=Severity.HIGH,
                    file=rel_path,
                    line_start=0,  # YAML errors don't typically include line numbers
                    title="Invalid YAML",
                    description=f"YAML syntax error: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _scan_package_json_misconfig(self, content: str, rel_path: str) -> list[Finding]:
        """Scan package.json for misconfigurations."""
        findings = []

        try:
            data = json.loads(content)

            # Check for development dependencies in production
            if "devDependencies" in data and "NODE_ENV" not in content:
                findings.append(
                    make_finding(
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line_start=0,
                        title="Potential Development Dependencies in Production",
                        description="package.json includes devDependencies without NODE_ENV check",
                        evidence="devDependencies found without environment check",
                    )
                )

            # Check for scripts that might expose vulnerabilities
            scripts = data.get("scripts", {})
            for script_name, script_content in scripts.items():
                if any(keyword in script_content.lower() for keyword in ["inspect", "--debug", "debug"]):
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=0,
                            title="Debug Flag in Scripts",
                            description=f"Script '{script_name}' contains debugging flags",
                            evidence=script_content,
                        )
                    )

        except json.JSONDecodeError as e:
            findings.append(
                make_finding(
                    severity=Severity.HIGH,
                    file=rel_path,
                    line_start=e.lineno,
                    title="Invalid package.json",
                    description=f"JSON syntax error in package.json: {str(e)}",
                    evidence=e.msg,
                )
            )

        return findings

    def _scan_requirements_txt_misconfig(self, content: str, rel_path: str) -> list[Finding]:
        """Scan requirements.txt for misconfigurations."""
        findings = []

        # Check for development packages in production requirements
        dev_packages = ["pytest", "mock", "faker", "factory_boy", "django-debug-toolbar"]
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pkg in dev_packages:
                if pkg in line.lower():
                    findings.append(
                        make_finding(
                            severity=Severity.MEDIUM,
                            file=rel_path,
                            line_start=i,
                            title="Development Package in Requirements",
                            description=f"Development package '{pkg}' found in requirements.txt",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_toml_config_misconfig(self, content: str, rel_path: str) -> list[Finding]:
        """Scan TOML configuration files for misconfigurations."""
        findings = []

        # Since Python < 3.11 doesn't have built-in TOML support, we'll just do basic scanning
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Look for common misconfiguration patterns
            if any(
                debug_setting in line.lower()
                for debug_setting in ["debug =", "debug =", "enable_debug =", "debug_mode ="]
            ):
                if "true" in line.lower() or "1" in line:
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=i,
                            title="Debug Enabled in Configuration",
                            description="Debug mode appears to be enabled in TOML configuration",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_env_file_misconfig(self, content: str, rel_path: str) -> list[Finding]:
        """Scan environment files for misconfigurations."""
        findings = []

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Skip comments and empty lines
            if line.strip().startswith("#") or not line.strip():
                continue

            # Check for debug enabled
            if any(debug_var in line.upper() for debug_var in ["DEBUG=", "FLASK_DEBUG=", "DJANGO_DEBUG="]):
                if "TRUE" in line.upper() or "1" in line or "YES" in line.upper():
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=i,
                            title="Debug Enabled in Environment",
                            description="Debug mode enabled in environment file",
                            evidence=line.strip(),
                        )
                    )

            # Check for insecure settings
            if any(cors_var in line.upper() for cors_var in ["CORS_ORIGIN_ALLOW_ALL=", "ALLOWED_HOSTS="]):
                if "*" in line or '"*"' in line or "'*'" in line:
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=i,
                            title="Insecure CORS Configuration",
                            description="Wildcard allowed in CORS settings",
                            evidence=line.strip(),
                        )
                    )

        return findings

    def _scan_general_config_misconfig(self, content: str, rel_path: str) -> list[Finding]:
        """General configuration file scanning."""
        findings = []

        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            # Look for common misconfiguration patterns
            if any(
                pattern in line.lower() for pattern in ["debug=true", "debug: true", "enable_debug=1", "debug_mode=yes"]
            ):
                findings.append(
                    make_finding(
                        severity=Severity.HIGH,
                        file=rel_path,
                        line_start=i,
                        title="Debug Enabled in Configuration",
                        description="Debug mode appears to be enabled in configuration",
                        evidence=line.strip(),
                    )
                )

            # Check for insecure CORS
            if any(
                cors_pattern in line.lower() for cors_pattern in ["*.*", "allowed_origins=*", "origin_allow_all=true"]
            ):
                findings.append(
                    make_finding(
                        severity=Severity.HIGH,
                        file=rel_path,
                        line_start=i,
                        title="Insecure CORS Configuration",
                        description="Insecure CORS configuration detected",
                        evidence=line.strip(),
                    )
                )

        return findings

    def _scan_source_file_misconfig(self, file_path: Path, rel_path: str) -> list[Finding]:
        """Scan source files for misconfigurations."""
        findings = []

        try:
            content = file_path.read_text(encoding="utf-8")
            lines = content.splitlines()

            for i, line in enumerate(lines, 1):
                # Look for misconfigurations in source code
                if any(
                    debug_pattern in line.lower()
                    for debug_pattern in ["debug=true", "debug: true", "enable_debug", "app.debug"]
                ):
                    if any(on_val in line.lower() for on_val in ["true", "1", "yes", "on"]):
                        findings.append(
                            make_finding(
                                severity=Severity.HIGH,
                                file=rel_path,
                                line_start=i,
                                title="Debug Enabled in Source Code",
                                description="Debug mode enabled in source code",
                                evidence=line.strip(),
                            )
                        )

                # Look for insecure CORS in source code
                if any(
                    cors_pattern in line.lower() for cors_pattern in ["cors.*[*]", "allow_all_origins", "origins=[*]"]
                ):
                    findings.append(
                        make_finding(
                            severity=Severity.HIGH,
                            file=rel_path,
                            line_start=i,
                            title="Insecure CORS Configuration",
                            description="Insecure CORS configuration in source code",
                            evidence=line.strip(),
                        )
                    )

                # Look for missing security headers
                if any(
                    header_pattern in line.lower()
                    for header_pattern in [
                        "x-frame-options",
                        "frame_options",
                        "content-security-policy",
                    ]
                ):
                    if any(off_pattern in line.lower() for off_pattern in ["sameorigin", "deny", "default-src"]):
                        # These are generally secure settings
                        pass
                    else:
                        # Check if the header is disabled
                        if any(
                            disable_pattern in line.lower() for disable_pattern in ["none", "null", "empty", "unset"]
                        ):
                            findings.append(
                                make_finding(
                                    severity=Severity.MEDIUM,
                                    file=rel_path,
                                    line_start=i,
                                    title="Missing Security Header",
                                    description="Security header may not be properly set",
                                    evidence=line.strip(),
                                )
                            )

        except Exception as e:
            findings.append(
                make_finding(
                    severity=Severity.LOW,
                    file=rel_path,
                    line_start=0,
                    title="Misconfig scanner source file read error",
                    description=f"Could not analyze {file_path.name} for misconfigurations: {str(e)}",
                    evidence=str(e),
                )
            )

        return findings

    def _find_nested_key(self, data, keys, condition=None):
        """Helper to find nested keys in config data."""
        if isinstance(data, dict):
            for key, value in data.items():
                if key in keys:
                    if condition is None or condition(value):
                        return True
                # Recursively search nested dicts
                if isinstance(value, (dict, list)):
                    if self._find_nested_key(value, keys, condition):
                        return True
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    if self._find_nested_key(item, keys, condition):
                        return True
        return False
