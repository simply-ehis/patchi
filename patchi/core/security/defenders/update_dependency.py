"""Adapter: update_dependency — detect package manager, update vulnerable package."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .base import BaseAdapter, DefendResult, DefenseAction

_log = logging.getLogger("patchi.security.defenders.update_dep")

# Package managers and their update commands
_PACKAGE_MANAGERS: list[dict] = [
    {
        "name": "pip",
        "check": ["pip", "--version"],
        "update": ["pip", "install", "--upgrade"],
        "files": ["requirements.txt", "Pipfile", "pyproject.toml"],
    },
    {
        "name": "npm",
        "check": ["npm", "--version"],
        "update": ["npm", "update"],
        "files": ["package.json"],
    },
    {
        "name": "yarn",
        "check": ["yarn", "--version"],
        "update": ["yarn", "upgrade"],
        "files": ["package.json"],
    },
    {
        "name": "cargo",
        "check": ["cargo", "--version"],
        "update": ["cargo", "update"],
        "files": ["Cargo.toml"],
    },
    {"name": "go", "check": ["go", "version"], "update": ["go", "get", "-u"], "files": ["go.mod"]},
    {
        "name": "gem",
        "check": ["gem", "--version"],
        "update": ["gem", "update"],
        "files": ["Gemfile"],
    },
    {
        "name": "nuget",
        "check": ["dotnet", "--version"],
        "update": ["dotnet", "package", "update"],
        "files": ["*.csproj", "packages.config"],
    },
    {
        "name": "composer",
        "check": ["composer", "--version"],
        "update": ["composer", "update"],
        "files": ["composer.json"],
    },
]


def detect_package_manager(root: Path) -> str | None:
    """Detect which package manager is available in the project."""
    for pm in _PACKAGE_MANAGERS:
        try:
            r = subprocess.run(pm["check"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                for f in pm["files"]:
                    matches = list(root.glob(f))
                    if matches:
                        return pm["name"]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def detect_manifest(root: Path) -> Path | None:
    """Detect project manifest file."""
    for pattern in [
        "pyproject.toml",
        "package.json",
        "Cargo.toml",
        "go.mod",
        "Gemfile",
        "build.gradle",
        "pom.xml",
    ]:
        matches = list(root.glob(pattern))
        if matches:
            return matches[0]
    return None


class UpdateDependencyAdapter(BaseAdapter):
    """Update a vulnerable dependency via detected package manager."""

    action_type = "update_dependency"

    def execute(self, action: DefenseAction) -> DefendResult:
        pkg = Path(action.target).name if action.target else ""
        if not pkg:
            return DefendResult(
                action="skipped",
                reason="No package specified for update",
                defense_action=action,
            )

        pm_name = detect_package_manager(self.root)
        if not pm_name:
            return DefendResult(
                action="queued",
                reason="No supported package manager detected (tried pip, npm, yarn, cargo, go, gem, nuget, composer)",
                defense_action=action,
            )

        pm_config = next((p for p in _PACKAGE_MANAGERS if p["name"] == pm_name), None)
        if not pm_config:
            return DefendResult(
                action="blocked",
                reason=f"Package manager '{pm_name}' config not found",
                defense_action=action,
            )

        try:
            cmd = pm_config["update"] + [pkg]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                manifest = detect_manifest(self.root)
                if manifest and manifest.exists():
                    try:
                        text = manifest.read_text(encoding="utf-8")
                        text = text.replace(
                            f"{pkg}==",
                            f"{pkg}==  # updated by Patchi",
                        )
                        manifest.write_text(text, encoding="utf-8")
                    except Exception as e:
                        _log.warning("UpdateDependencyAdapter failed to annotate manifest: %s", e)
                return DefendResult(
                    action="applied",
                    reason=f"Updated {pkg} via {pm_name} successfully",
                    defense_action=action,
                )
            else:
                return DefendResult(
                    action="blocked",
                    reason=f"{pm_name} update failed: {result.stderr[:200]}",
                    defense_action=action,
                )
        except FileNotFoundError:
            return DefendResult(
                action="skipped",
                reason=f"{pm_name} not found — cannot update dependencies",
                defense_action=action,
            )
        except subprocess.TimeoutExpired:
            return DefendResult(
                action="blocked",
                reason=f"{pm_name} update timed out",
                defense_action=action,
            )
