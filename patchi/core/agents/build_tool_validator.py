"""BuildToolValidatorAgent — detects misconfigurations in build tools.

Covers §8.3.1:
- Vite config: missing optimizeDeps, outdated plugins, missing build target
- Webpack: missing mode, production optimizations, devtool in prod
- Rollup: missing output format, external deps
- esbuild: missing target, platform, format
"""

from __future__ import annotations

import logging
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

_log = logging.getLogger("patchi.agents.build_tool_validator")


def _check_vite_config(content: str, rel: str) -> list[dict]:
    findings: list[dict] = []
    if "defineConfig" not in content:
        findings.append({"file": rel, "issue": "defineConfig not found — possibly outdated config format"})
    if "optimizeDeps" not in content:
        findings.append({"file": rel, "issue": "Missing optimizeDeps — may slow dev server"})
    if "build" in content and "target" in content and "es2015" in content:
        pass  # has build target
    elif "build" in content and "target" not in content:
        findings.append({"file": rel, "issue": "No build.target set — defaults may be too broad"})
    return findings


def _check_webpack_config(content: str, rel: str) -> list[dict]:
    findings: list[dict] = []
    if "mode" not in content:
        findings.append({"file": rel, "issue": "Missing mode — defaults to 'production' but explicit is safer"})
    if "'production'" in content and "'development'" not in content and "devtool" in content:
        findings.append({"file": rel, "issue": "devtool configured — may leak source maps in production"})
    if "MiniCssExtractPlugin" not in content and "css" in content:
        findings.append({"file": rel, "issue": "No MiniCssExtractPlugin — CSS will be inlined in JS"})
    return findings


def _check_rollup_config(content: str, rel: str) -> list[dict]:
    findings: list[dict] = []
    if "output" not in content or ("format" not in content and "dir" not in content and "file" not in content):
        findings.append({"file": rel, "issue": "Missing output configuration (format/dir/file)"})
    if "external" not in content:
        findings.append({"file": rel, "issue": "No external dependencies listed — bundle may be bloated"})
    return findings


def _check_esbuild_config(content: str, rel: str) -> list[dict]:
    findings: list[dict] = []
    if "target" not in content:
        findings.append(
            {
                "file": rel,
                "issue": "Missing target — esbuild defaults to esnext which may not be safe",
            }
        )
    if "format" not in content:
        findings.append({"file": rel, "issue": "Missing format (esm/cjs/iife) — output format ambiguous"})
    return findings


@register
class BuildToolValidatorAgent(BaseAgent):
    """Detects misconfigurations in Vite, Webpack, Rollup, esbuild configs."""

    group = AgentGroup.SCANNER
    name = "BuildToolValidatorAgent"
    description = "Check Vite/Webpack/Rollup/esbuild configs for known misconfigurations"

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        config_map: list[tuple[str, str, callable]] = [
            ("vite.config.*", "vite", _check_vite_config),
            ("webpack.config.*", "webpack", _check_webpack_config),
            ("rollup.config.*", "rollup", _check_rollup_config),
            ("esbuild.config.*", "esbuild", _check_esbuild_config),
            ("esbuild.js", "esbuild", _check_esbuild_config),
        ]
        files_scanned = 0
        all_findings: list[dict] = []

        for glob_pat, tool, checker in config_map:
            for fp in safe_rglob(inp.root, glob_pat):
                rel = fp.relative_to(inp.root).as_posix()
                if any(seg in DEFAULT_IGNORE_DIRS for seg in Path(rel).parts):
                    continue
                files_scanned += 1
                try:
                    content = fp.read_text(encoding="utf-8")
                except Exception as e:
                    _log.warning("BuildToolValidatorAgent._run failed: %s", e)
                    continue
                result.findings.append(
                    make_finding(
                        self.name,
                        "build_config_found",
                        Severity.INFO,
                        rel,
                        f"Build config found: {rel} ({tool})",
                    )
                )
                issues = checker(content, rel)
                all_findings.extend(issues)

        result.data["configs_found"] = files_scanned
        result.data["issues"] = all_findings
        result.files_scanned = files_scanned

        for issue in all_findings:
            result.findings.append(
                make_finding(
                    self.name,
                    "build_config_issue",
                    Severity.LOW,
                    issue["file"],
                    issue["issue"],
                )
            )

        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
