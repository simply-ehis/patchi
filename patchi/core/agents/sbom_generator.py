"""SBOMGeneratorAgent — generates CycloneDX/SPDX Software Bill of Materials.

Covers §11.5:
- Parse dependency manifests (package.json, requirements.txt, Cargo.toml, go.mod, Gemfile, etc.)
- Generate CycloneDX 1.5-compatible JSON output
- Write to .patchi/sbom.cdx.json

Language-agnostic: supports npm, pip, cargo, go, bundler, composer ecosystems.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

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

_ECOSYSTEM_MAP = {
    "package.json": ("npm", "JavaScript"),
    "requirements.txt": ("pypi", "Python"),
    "pyproject.toml": ("pypi", "Python"),
    "Pipfile": ("pypi", "Python"),
    "poetry.lock": ("pypi", "Python"),
    "Cargo.toml": ("crates", "Rust"),
    "Cargo.lock": ("crates", "Rust"),
    "go.mod": ("go", "Go"),
    "go.sum": ("go", "Go"),
    "Gemfile": ("gem", "Ruby"),
    "Gemfile.lock": ("gem", "Ruby"),
    "composer.json": ("composer", "PHP"),
    "yarn.lock": ("npm", "JavaScript"),
    "pnpm-lock.yaml": ("npm", "JavaScript"),
}

_COMPONENT_TYPES = {
    "npm": "library",
    "pypi": "library",
    "crates": "library",
    "go": "library",
    "gem": "library",
    "composer": "library",
}


_log = logging.getLogger("patchi.agents.sbom_generator")

_MAX_DEPS = 5000


def _parse_deps(fp: Path) -> list[dict]:
    deps: list[dict] = []
    try:
        content = fp.read_text(encoding="utf-8")
    except Exception as e:
        _log.warning("_parse_deps failed: %s", e)
        return deps

    if fp.name == "package.json":
        try:
            data = json.loads(content)
            all_deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for name, ver in all_deps.items():
                deps.append({"name": name, "version": ver.lstrip("^~>=<")})
        except json.JSONDecodeError:
            pass
    elif fp.name == "requirements.txt":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            for sep in ["==", ">=", "<="]:
                if sep in line:
                    name, ver = line.split(sep, 1)
                    deps.append({"name": name.strip(), "version": ver.strip()})
                    break
            else:
                deps.append({"name": line, "version": "unknown"})
    elif fp.name == "Cargo.toml":
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[dependencies]") or stripped.startswith("[dev-dependencies]"):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False
            if in_deps and "=" in stripped:
                m = re.match(r"(\w[\w\-_]*)", stripped)
                if m:
                    name = m.group(1)
                    ver_part = stripped[len(name) :].strip("= ").strip('"')
                    deps.append({"name": name, "version": ver_part})
    elif fp.name == "pyproject.toml":
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("dependencies = ["):
                in_deps = True
                continue
            if in_deps:
                if stripped == "]":
                    in_deps = False
                else:
                    m = re.match(r'["\']([^"\'>]+?)([>=<~!]+)([^"\']+)["\'],?', stripped)
                    if m:
                        deps.append({"name": m.group(1), "version": m.group(3)})
    elif fp.name == "go.mod":
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ") or stripped.startswith("\trequire "):
                parts = stripped.replace("require ", "").split()
                if len(parts) >= 2:
                    deps.append({"name": parts[0], "version": parts[1]})
    return deps


def _build_cyclonedx(
    root: Path,
    deps_by_eco: dict[str, list[dict]],
    *,
    max_deps: int = _MAX_DEPS,
) -> dict:
    components: list[dict] = []
    for eco, dep_list in deps_by_eco.items():
        comp_type = _COMPONENT_TYPES.get(eco, "library")
        for dep in dep_list:
            components.append(
                {
                    "type": comp_type,
                    "name": dep["name"],
                    "version": dep["version"],
                    "purl": f"pkg:{eco}/{dep['name']}@{dep['version']}",
                    "bom-ref": f"pkg:{eco}/{dep['name']}@{dep['version']}",
                }
            )

    truncated = False
    total_before = len(components)
    if max_deps > 0 and total_before > max_deps:
        components.sort(key=lambda c: (c["name"], c.get("purl", "")))
        components = components[:max_deps]
        truncated = True
        _log.warning(
            "SBOM truncated: %d deps exceeds limit of %d — keeping first %d "
            "(sorted alphabetically)",
            total_before,
            max_deps,
            max_deps,
        )

    metadata: dict = {
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": [{"name": "Patchi", "version": "1.0"}],
        "component": {
            "type": "application",
            "name": root.name,
        },
    }
    if truncated:
        metadata["truncated"] = True
        metadata["truncated_original_count"] = total_before
        metadata["truncated_limit"] = max_deps

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4().hex}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }


@register
class SBOMGeneratorAgent(BaseAgent):
    """Generates CycloneDX Software Bill of Materials from dependency manifests."""

    group = AgentGroup.SCANNER
    name = "SBOMGeneratorAgent"
    description = "Generate CycloneDX SBOM from package.json, requirements.txt, Cargo.toml, go.mod, Gemfile, etc."

    def _try_external(self, inp: AgentInput) -> dict | None:
        """Try cdxgen then syft as subprocess — 20+ ecos depth, fail-open to internal parser."""
        import shutil
        import subprocess as _sp

        # cdxgen: npx @cyclonedx/cdxgen -o /tmp/sbom.json
        for cmd in (
            [
                "npx",
                "--yes",
                "@cyclonedx/cdxgen",
                "-o",
                str(inp.root / ".patchi" / "sbom.cdxgen.json"),
                "--no-recurse",
            ],
            ["syft", str(inp.root), "-o", "cyclonedx-json"],
        ):
            if not shutil.which(cmd[0]):
                continue
            try:
                proc = _sp.run(cmd, capture_output=True, text=True, timeout=120, cwd=str(inp.root))
                out = proc.stdout.strip()
                # cdxgen writes file, syft prints json
                cand = inp.root / ".patchi" / "sbom.cdxgen.json"
                if cand.exists():
                    return json.loads(cand.read_text(encoding="utf-8"))
                if out and out.startswith("{"):
                    return json.loads(out)
            except Exception as e:
                _log.debug("SBOM external %s failed: %s", cmd[0], e)
        return None

    def _run(self, inp: AgentInput, result: AgentResult) -> None:
        max_deps = (inp.extra or {}).get("sbom_limit", _MAX_DEPS)

        # Try external depth first
        ext = self._try_external(inp)
        if ext and ext.get("components"):
            sbom = ext
            total = len(ext.get("components", []))
            sbom_dir = inp.root / ".patchi"
            sbom_dir.mkdir(parents=True, exist_ok=True)
            sbom_path = sbom_dir / "sbom.cdx.json"
            try:
                sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
                result.findings.append(
                    make_finding(
                        self.name,
                        "sbom_generated",
                        Severity.INFO,
                        str(sbom_path.relative_to(inp.root)),
                        f"SBOM (external) {total} components",
                    )
                )
            except Exception as e:
                result.add_error(f"Failed to write SBOM: {e}")
            result.data["sbom_path"] = str(sbom_path)
            result.data["total_components"] = total
            result.data["ecosystems"] = ["external"]
            result.data["sbom"] = sbom
            result.data["external"] = True
            result.status = AgentStatus.DONE
            return

        deps_by_eco: dict[str, list[dict]] = {}
        files_scanned = 0

        for manifest in _ECOSYSTEM_MAP:
            for fp in safe_rglob(inp.root, manifest):
                rel = fp.relative_to(inp.root).as_posix()
                eco, _ = _ECOSYSTEM_MAP[manifest]
                deps = _parse_deps(fp)
                if deps:
                    deps_by_eco.setdefault(eco, []).extend(deps)
                    result.findings.append(
                        make_finding(
                            self.name,
                            "sbom_source",
                            Severity.INFO,
                            rel,
                            f"SBOM source: {rel} ({len(deps)} deps)",
                        )
                    )
                    files_scanned += 1

        if not deps_by_eco:
            result.findings.append(
                make_finding(
                    self.name,
                    "no_sbom_sources",
                    Severity.INFO,
                    "",
                    "No dependency manifests found — cannot generate SBOM",
                )
            )
            result.status = AgentStatus.DONE
            return

        sbom = _build_cyclonedx(inp.root, deps_by_eco, max_deps=max_deps)
        total_deps = sum(len(d) for d in deps_by_eco.values())

        # Write SBOM to .patchi/ directory
        sbom_dir = inp.root / ".patchi"
        sbom_dir.mkdir(parents=True, exist_ok=True)
        sbom_path = sbom_dir / "sbom.cdx.json"
        try:
            sbom_path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
            result.findings.append(
                make_finding(
                    self.name,
                    "sbom_generated",
                    Severity.INFO,
                    str(sbom_path.relative_to(inp.root)),
                    f"SBOM generated: {total_deps} components across {len(deps_by_eco)} ecosystems",
                    detail=str(sbom_path),
                )
            )
        except Exception as e:
            result.add_error(f"Failed to write SBOM: {e}")

        result.data["sbom_path"] = str(sbom_path)
        result.data["total_components"] = total_deps
        result.data["ecosystems"] = list(deps_by_eco.keys())
        result.data["sbom"] = sbom
        result.files_scanned = files_scanned
        if result.status == AgentStatus.RUNNING:
            result.status = AgentStatus.DONE
