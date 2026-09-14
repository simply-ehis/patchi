"""
Smart Project Reader — understands what the project is by reading its files.

Extracts:
- Project name and description from README, package.json, pyproject.toml
- Tech stack from dependencies
- Entry points and main modules
- Project structure and architecture patterns
- Critical paths that must never break

This feeds into the ContractBuilder to make the app contract
actually understand the project, not just pattern-match routes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger("patchi.brain.project_reader")


@dataclass
class ProjectInsight:
    """What the project reader understands about the project."""

    name: str = ""
    description: str = ""
    tech_stack: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    critical_dirs: list[str] = field(default_factory=list)
    project_type: str = ""  # "web-app", "cli", "library", "api", "desktop", etc.
    framework: str = ""
    language: str = ""
    dependencies: list[str] = field(default_factory=list)
    dev_dependencies: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    readme_summary: str = ""
    architecture_notes: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "tech_stack": self.tech_stack,
            "entry_points": self.entry_points,
            "critical_dirs": self.critical_dirs,
            "project_type": self.project_type,
            "framework": self.framework,
            "language": self.language,
            "dependencies": self.dependencies[:20],
            "readme_summary": self.readme_summary[:500],
        }


def read_project_insight(root: Path) -> ProjectInsight:
    """Read the project and build a comprehensive understanding."""
    insight = ProjectInsight()

    # Try multiple sources in order of reliability
    _read_readme(root, insight)
    _read_package_json(root, insight)
    _read_pyproject_toml(root, insight)
    _read_setup_cfg(root, insight)
    _read_requirements_txt(root, insight)
    _read_cargo_toml(root, insight)
    _read_go_mod(root, insight)
    _read_package_json_ts(root, insight)

    # Infer project type from structure
    _infer_project_type(root, insight)

    # Find entry points
    _find_entry_points(root, insight)

    # Find critical directories
    _find_critical_dirs(root, insight)

    return insight


def _read_readme(root: Path, insight: ProjectInsight) -> None:
    """Extract project info from README files."""
    for name in ["README.md", "README.rst", "README.txt", "README", "readme.md"]:
        readme_path = root / name
        if readme_path.is_file():
            try:
                content = readme_path.read_text(encoding="utf-8", errors="replace")
                lines = content.strip().splitlines()

                # Extract title (first # heading or first non-empty line)
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("# "):
                        insight.name = stripped[2:].strip()
                        break
                    elif stripped and not insight.name:
                        # First non-empty line as fallback
                        insight.name = stripped[:80]
                        break

                # Extract description (first paragraph after title)
                found_title = False
                desc_lines = []
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("# "):
                        found_title = True
                        continue
                    if found_title:
                        if stripped == "":
                            if desc_lines:
                                break
                            continue
                        if stripped.startswith("#"):
                            break
                        desc_lines.append(stripped)

                if desc_lines:
                    insight.description = " ".join(desc_lines)[:300]

                # Extract summary for brain context
                insight.readme_summary = "\n".join(lines[:50])[:500]
                break
            except Exception as e:
                _log.debug("Failed to read %s: %s", name, e)


def _read_package_json(root: Path, insight: ProjectInsight) -> None:
    """Extract project info from package.json."""
    pkg_path = root / "package.json"
    if not pkg_path.is_file():
        return

    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8"))
        if not insight.name:
            insight.name = data.get("name", "")
        if not insight.description:
            insight.description = data.get("description", "")

        # Dependencies
        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        insight.dependencies = list(deps.keys())
        insight.dev_dependencies = list(dev_deps.keys())

        # Tech stack from dependencies
        _infer_tech_stack_from_deps(insight, deps, dev_deps)

        # Scripts
        insight.scripts = data.get("scripts", {})

        # Entry points
        main = data.get("main", "")
        if main:
            insight.entry_points.append(main)

        bin_entry = data.get("bin", {})
        if isinstance(bin_entry, str):
            insight.entry_points.append(bin_entry)
        elif isinstance(bin_entry, dict):
            insight.entry_points.extend(bin_entry.values())

    except Exception as e:
        _log.debug("Failed to read package.json: %s", e)


def _read_pyproject_toml(root: Path, insight: ProjectInsight) -> None:
    """Extract project info from pyproject.toml."""
    toml_path = root / "pyproject.toml"
    if not toml_path.is_file():
        return

    try:
        import tomllib
    except ImportError:
        # Python < 3.11 fallback
        try:
            import tomli as tomllib
        except ImportError:
            return

    try:
        data = tomllib.loads(toml_path.read_text(encoding="utf-8"))

        # Project metadata
        project = data.get("project", {})
        if not insight.name:
            insight.name = project.get("name", "")
        if not insight.description:
            insight.description = project.get("description", "")

        insight.language = "python"

        # Dependencies
        deps = project.get("dependencies", [])
        insight.dependencies = [_dep_name(d) for d in deps]

        optional = project.get("optional-dependencies", {})
        for group_deps in optional.values():
            insight.dev_dependencies.extend([_dep_name(d) for d in group_deps])

        # Scripts / entry points
        scripts = data.get("project", {}).get("scripts", {})
        if scripts:
            insight.scripts.update(scripts)
            insight.entry_points.extend(scripts.values())

        # Build system hints
        build = data.get("build-system", {})
        build_backend = build.get("build-backend", "")
        if "setuptools" in build_backend:
            insight.tech_stack.append("setuptools")
        elif "poetry" in build_backend:
            insight.tech_stack.append("poetry")
        elif "hatchling" in build_backend:
            insight.tech_stack.append("hatchling")

        # Tool configs
        if "ruff" in data:
            insight.dev_dependencies.append("ruff")
        if "pytest" in data:
            insight.dev_dependencies.append("pytest")
        if "mypy" in data:
            insight.dev_dependencies.append("mypy")

        # Infer tech stack
        _infer_tech_stack_from_deps(
            insight,
            dict.fromkeys(insight.dependencies, ""),
            dict.fromkeys(insight.dev_dependencies, ""),
        )

    except Exception as e:
        _log.debug("Failed to read pyproject.toml: %s", e)


def _read_setup_cfg(root: Path, insight: ProjectInsight) -> None:
    """Extract from setup.cfg."""
    setup_path = root / "setup.cfg"
    if not setup_path.is_file():
        return

    try:
        import configparser

        cfg = configparser.ConfigParser()
        cfg.read(str(setup_path))

        if not insight.name:
            insight.name = cfg.get("metadata", "name", fallback="")
        if not insight.description:
            insight.description = cfg.get("metadata", "description", fallback="")
        insight.language = "python"
    except Exception as _exc:
        _log.debug("_read_setup_cfg skipped: %s", _exc)


def _read_requirements_txt(root: Path, insight: ProjectInsight) -> None:
    """Extract from requirements*.txt (Part 7: this ubiquitous manifest was
    invisible — requirements-only projects classified as 'unknown')."""
    import re as _re

    for name in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
        req_path = root / name
        if not req_path.is_file():
            continue
        try:
            for line in req_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-", " ")):
                    continue
                dep = _re.split(r"[=<>!~\s\[]", line, maxsplit=1)[0].strip()
                if dep and dep not in insight.dependencies:
                    insight.dependencies.append(dep)
            if insight.dependencies and not insight.language:
                insight.language = "python"
        except Exception as _exc:
            _log.debug("_read_requirements_txt skipped: %s", _exc)


def _read_cargo_toml(root: Path, insight: ProjectInsight) -> None:
    """Extract from Cargo.toml (Rust projects)."""
    cargo_path = root / "Cargo.toml"
    if not cargo_path.is_file():
        return

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            return

    try:
        data = tomllib.loads(cargo_path.read_text(encoding="utf-8"))
        pkg = data.get("package", {})
        insight.name = pkg.get("name", "")
        insight.description = pkg.get("description", "")
        insight.language = "rust"
        insight.tech_stack.append("cargo")

        deps = data.get("dependencies", {})
        insight.dependencies = list(deps.keys())
    except Exception as _exc:
        _log.debug("_read_cargo_toml skipped: %s", _exc)


def _read_go_mod(root: Path, insight: ProjectInsight) -> None:
    """Extract from go.mod (Go projects)."""
    go_mod = root / "go.mod"
    if not go_mod.is_file():
        return

    try:
        content = go_mod.read_text(encoding="utf-8")
        for line in content.splitlines():
            if line.startswith("module "):
                insight.name = line.split()[-1].split("/")[-1]
                insight.language = "go"
                break
    except Exception as _exc:
        _log.debug("_read_go_mod skipped: %s", _exc)


def _read_package_json_ts(root: Path, insight: ProjectInsight) -> None:
    """Read tsconfig.json for TypeScript projects."""
    tsconfig = root / "tsconfig.json"
    if not tsconfig.is_file():
        return

    try:
        data = json.loads(tsconfig.read_text(encoding="utf-8"))
        if "compilerOptions" in data:
            insight.tech_stack.append("typescript")
            if insight.language == "":
                insight.language = "typescript"
    except Exception as _exc:
        _log.debug("_read_package_json_ts skipped: %s", _exc)


def _infer_tech_stack_from_deps(
    insight: ProjectInsight,
    deps: dict,
    dev_deps: dict,
) -> None:
    """Infer tech stack from dependency names."""
    all_deps = set(list(deps.keys()) + list(dev_deps.keys()))

    framework_hints = {
        "fastapi": ("FastAPI", "web-app", "python"),
        "flask": ("Flask", "web-app", "python"),
        "django": ("Django", "web-app", "python"),
        "starlette": ("Starlette", "web-app", "python"),
        "uvicorn": ("uvicorn", "web-app", "python"),
        "react": ("React", "web-app", "javascript"),
        "vue": ("Vue", "web-app", "javascript"),
        "angular": ("Angular", "web-app", "javascript"),
        "next": ("Next.js", "web-app", "javascript"),
        "svelte": ("Svelte", "web-app", "javascript"),
        "express": ("Express", "api", "javascript"),
        "koa": ("Koa", "api", "javascript"),
        "hono": ("Hono", "api", "javascript"),
        "gin": ("Gin", "api", "go"),
        "fiber": ("Fiber", "api", "go"),
        "actix": ("Actix", "api", "rust"),
        "axum": ("Axum", "api", "rust"),
        "tauri": ("Tauri", "desktop", "rust"),
        "electron": ("Electron", "desktop", "javascript"),
    }

    for dep_name, (fw, ptype, lang) in framework_hints.items():
        if dep_name in all_deps:
            if fw not in insight.tech_stack:
                insight.tech_stack.append(fw)
            if not insight.project_type:
                insight.project_type = ptype
            if not insight.language:
                insight.language = lang
            insight.framework = fw

    # Dev tool hints
    dev_tools = {
        "pytest": "pytest",
        "jest": "jest",
        "vitest": "vitest",
        "mocha": "mocha",
        "eslint": "eslint",
        "prettier": "prettier",
        "ruff": "ruff",
        "mypy": "mypy",
        "typescript": "typescript",
        "playwright": "playwright",
        "cypress": "cypress",
    }
    for tool_name, tool_label in dev_tools.items():
        if tool_name in all_deps and tool_label not in insight.tech_stack:
            insight.tech_stack.append(tool_label)


def _infer_project_type(root: Path, insight: ProjectInsight) -> None:
    """Infer project type from structure if not already known."""
    if insight.project_type:
        return

    indicators = {
        "web-app": [
            "templates/",
            "static/",
            "public/",
            "pages/",
            "components/",
            "app.py",
            "main.py",
            "server.py",
            "index.html",
        ],
        "api": [
            "routes/",
            "handlers/",
            "controllers/",
            "endpoints/",
            "api/",
            "openapi",
            "swagger",
        ],
        "cli": [
            "cli/",
            "commands/",
            "cli.py",
            "main.py",
            "__main__.py",
        ],
        "library": [
            "src/",
            "lib/",
            "__init__.py",
        ],
        "desktop": [
            "electron/",
            "tauri/",
            "src-tauri/",
            "main.js",
        ],
    }

    scores: dict[str, int] = {}
    for ptype, indicators_list in indicators.items():
        score = 0
        for indicator in indicators_list:
            if (root / indicator).exists():
                score += 1
        if score:
            scores[ptype] = score

    if scores:
        insight.project_type = max(scores, key=scores.get)
    else:
        insight.project_type = "unknown"


def _find_entry_points(root: Path, insight: ProjectInsight) -> None:
    """Find main entry points of the project."""
    # Check pyproject.toml scripts
    if insight.scripts:
        for name, cmd in insight.scripts.items():
            if "python" in cmd or "patchi" in cmd:
                insight.entry_points.append(f"pyproject:{name}")

    # Check common entry points
    candidates = [
        "main.py",
        "app.py",
        "server.py",
        "index.py",
        "main.js",
        "index.js",
        "app.js",
        "server.js",
        "main.ts",
        "index.ts",
        "app.ts",
        "src/main.rs",
        "src/lib.rs",
        "main.go",
    ]

    for candidate in candidates:
        path = root / candidate
        if path.exists() and candidate not in insight.entry_points:
            insight.entry_points.append(candidate)

    # Check for __main__.py (Python package entry point)
    for pkg_dir in ["patchi", "src"]:
        main_file = root / pkg_dir / "__main__.py"
        if main_file.exists():
            insight.entry_points.append(f"{pkg_dir}/__main__.py")

    # Check for CLI entry points in setup.py/setup.cfg
    for setup_file in ["setup.py", "setup.cfg"]:
        setup_path = root / setup_file
        if setup_path.is_file():
            try:
                content = setup_path.read_text(encoding="utf-8", errors="replace")
                if "console_scripts" in content or "entry_points" in content:
                    insight.entry_points.append(setup_file)
            except Exception as _exc:
                _log.debug("_find_entry_points skipped: %s", _exc)


def _find_critical_dirs(root: Path, insight: ProjectInsight) -> None:
    """Find directories that are critical to the project."""
    # Skip common non-critical directories
    skip_dirs = {
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "node_modules",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".eggs",
        "*.egg-info",
        ".tox",
        ".nox",
        "htmlcov",
    }

    # Patterns that indicate critical directories
    critical_patterns = {
        "auth": ["auth", "authentication", "authorization", "login", "session"],
        "api": ["api", "routes", "handlers", "controllers", "endpoints"],
        "models": ["models", "schemas", "entities", "types"],
        "services": ["services", "business", "domain", "core"],
        "database": ["db", "database", "migrations", "models"],
        "config": ["config", "settings", "env"],
        "cli": ["cli", "commands"],
        "web": ["web", "templates", "static", "views"],
        "core": ["core", "lib", "src"],
        "tests": ["tests", "test", "spec"],
    }

    for dirpath in [d for d in root.iterdir() if d.is_dir()]:
        if dirpath.name.startswith(".") or dirpath.name in skip_dirs:
            continue
        # Skip directories with only __pycache__ or hidden files
        try:
            contents = list(dirpath.iterdir())
            real_contents = [c for c in contents if not c.name.startswith(".") and c.name != "__pycache__"]
            if not real_contents:
                continue
        except PermissionError:
            continue

        dir_lower = dirpath.name.lower()
        matched = False
        for _category, patterns in critical_patterns.items():
            if any(p in dir_lower for p in patterns):
                if dirpath.name not in insight.critical_dirs:
                    insight.critical_dirs.append(dirpath.name)
                matched = True
                break

        # If no pattern matched, check if it's a source code directory
        if not matched:
            # Check if it has Python/JS/TS files
            has_source = False
            try:
                for f in dirpath.iterdir():
                    if f.suffix in (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs"):
                        has_source = True
                        break
            except PermissionError:
                pass
            if has_source and dirpath.name not in insight.critical_dirs:
                insight.critical_dirs.append(dirpath.name)


def _dep_name(dep_string: str) -> str:
    """Extract package name from a dependency string like 'requests>=2.0'."""
    name = dep_string.split(">")[0].split("<")[0].split("=")[0].split("!")[0].split("[")[0].strip()
    return name.lower().replace("-", "_")
