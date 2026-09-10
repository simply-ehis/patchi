"""
Framework detection for Patchi's Brain.

Reads project config files (package.json, requirements.txt, etc.)
and infers the tech stack used by the project.

Returns a FrameworkInfo object with: name, language, version (if detectable),
config file path, and confidence score.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patchi.core.brain.file_corpus import FileCorpus

_log = logging.getLogger("patchi.brain.framework")


@dataclass
class FrameworkInfo:
    name: str  # e.g. "Next.js", "FastAPI", "Express"
    language: str  # primary language
    version: str  # detected version or "" if unknown
    config_file: str  # relative path to the source config file
    confidence: float  # 0.0 – 1.0
    extra: dict = field(default_factory=dict)  # additional metadata

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "language": self.language,
            "version": self.version,
            "config_file": self.config_file,
            "confidence": self.confidence,
            **self.extra,
        }


@dataclass
class StackInfo:
    """Full picture of the project's tech stack."""

    primary_language: str = ""
    frameworks: list[FrameworkInfo] = field(default_factory=list)
    runtime: str = ""  # "node", "python", "php", "browser", etc.
    package_manager: str = ""  # "npm", "yarn", "pnpm", "pip", "cargo", etc.
    test_framework: str = ""  # "jest", "pytest", "phpunit", etc.
    has_typescript: bool = False
    has_docker: bool = False
    has_ci: bool = False  # any CI config found
    detected_files: list[str] = field(default_factory=list)
    language_breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "primary_language": self.primary_language,
            "frameworks": [f.to_dict() for f in self.frameworks],
            "runtime": self.runtime,
            "package_manager": self.package_manager,
            "test_framework": self.test_framework,
            "has_typescript": self.has_typescript,
            "has_docker": self.has_docker,
            "has_ci": self.has_ci,
            "detected_files": self.detected_files,
            "language_breakdown": self.language_breakdown,
        }


# ── Detector ───────────────────────────────────────────────────────────────────


class FrameworkDetector:
    """
    Detects frameworks and runtime from project config files.

    Usage:
        detector = FrameworkDetector(project_root)
        stack = detector.detect()
    """

    def __init__(self, root: Path, corpus: FileCorpus | None = None):
        self.root = root
        self._corpus = corpus

    def compute_language_breakdown(self) -> dict[str, int]:
        """Count files per language from corpus (fast, no parsing needed)."""
        if not self._corpus:
            return {}
        ext_to_lang = {
            ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
            ".ts": "TypeScript", ".tsx": "TypeScript",
            ".java": "Java", ".cs": "C#", ".go": "Go", ".rs": "Rust",
            ".php": "PHP", ".rb": "Ruby", ".swift": "Swift",
            ".kt": "Kotlin", ".scala": "Scala",
            ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".c": "C",
            ".h": "C/C++", ".hpp": "C++",
            ".pl": "Perl", ".pm": "Perl", ".lua": "Lua", ".r": "R",
            ".m": "Objective-C", ".mm": "Objective-C++",
            ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
            ".ps1": "PowerShell",
            ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
            ".toml": "TOML", ".xml": "XML",
            ".html": "HTML", ".htm": "HTML",
            ".css": "CSS", ".scss": "SCSS", ".sass": "Sass",
            ".vue": "Vue", ".svelte": "Svelte",
        }
        counts: dict[str, int] = {}
        for ext, lang in ext_to_lang.items():
            try:
                files = self._corpus.by_ext(ext)
                if files:
                    counts[lang] = counts.get(lang, 0) + len(files)
            except Exception:
                pass
        return counts

    def _rglob(self, pattern: str) -> list[Path]:
        """Like Path.rglob, using pre-built corpus when available."""
        if self._corpus:
            ext = Path(pattern).suffix
            if not ext:
                return list(self.root.rglob(pattern))
            return [e.abs_path for e in self._corpus.by_ext(ext)]
        return list(self.root.rglob(pattern))

    def detect(self) -> StackInfo:
        stack = StackInfo()

        # Node.js / JavaScript / TypeScript
        pkg_json = self.root / "package.json"
        if pkg_json.exists():
            self._detect_node(pkg_json, stack)

        # Python — search root and common subdirs (backend/*, server/*)
        pyconf_candidates = ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"]
        python_found = False
        for pyconf in pyconf_candidates:
            path = self.root / pyconf
            if path.exists():
                self._detect_python(path, stack)
                python_found = True
                break
        if not python_found:
            for sub in ["backend", "server", "api", "src"]:
                for pyconf in pyconf_candidates:
                    candidate = self.root / sub / pyconf
                    if candidate.exists():
                        self._detect_python(candidate, stack)
                        python_found = True
                        break
                if python_found:
                    break

        # PHP
        composer = self.root / "composer.json"
        if composer.exists():
            self._detect_php(composer, stack)

        # Rust — search root and common subdirs (src-tauri, crates/*)
        cargo_toml = self.root / "Cargo.toml"
        if not cargo_toml.exists():
            for sub in ["src-tauri", "crates", "backend"]:
                candidate = self.root / sub / "Cargo.toml"
                if candidate.exists():
                    cargo_toml = candidate
                    break
        if cargo_toml.exists():
            self._detect_rust(cargo_toml, stack)

        # Svelte (standalone Svelte files without SvelteKit)
        svelte_files = self._rglob("*.svelte")
        if svelte_files:
            has_kit = any(
                "sveltekit" in f.name.lower() or "kit" in f.name.lower() for f in stack.frameworks
            )
            if not has_kit:
                stack.frameworks.append(
                    FrameworkInfo(
                        name="Svelte (standalone)",
                        language="TypeScript" if stack.has_typescript else "JavaScript",
                        version="",
                        config_file="",
                        confidence=0.7,
                        extra={"file_count": len(svelte_files)},
                    )
                )

        # Java — pom.xml or build.gradle
        for jf in ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"]:
            jpath = self.root / jf
            if jpath.exists():
                self._detect_java(jpath, stack)
                break

        # C# — *.csproj (project-specific filename, so glob rather than fixed name)
        csproj_files = self._rglob("*.csproj")
        if csproj_files:
            self._detect_csharp(csproj_files[0], stack)

        # Go — go.mod
        go_mod = self.root / "go.mod"
        if go_mod.exists():
            self._detect_go(go_mod, stack)

        # C/C++ — CMakeLists.txt or Makefile (non-Bash)
        for cf in ["CMakeLists.txt", "Makefile"]:
            cpath = self.root / cf
            if cpath.exists():
                self._detect_c_cpp(cpath, stack)
                break

        # Swift — Package.swift or .swift files
        pkg_swift = self.root / "Package.swift"
        if pkg_swift.exists():
            self._detect_swift(pkg_swift, stack)
        elif self._rglob("*.swift"):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Swift", language="Swift", version="", config_file="", confidence=0.6
                )
            )

        # Ruby — Gemfile or .rb files
        gemfile = self.root / "Gemfile"
        if gemfile.exists():
            self._detect_ruby(gemfile, stack)
        elif self._rglob("*.rb"):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Ruby", language="Ruby", version="", config_file="", confidence=0.6
                )
            )

        # Shell / Bash (simple presence check)
        for bash_file in ["Makefile", "deploy.sh", "build.sh"]:
            if (self.root / bash_file).exists():
                stack.detected_files.append(bash_file)

        # Docker
        for df in ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"]:
            if (self.root / df).exists():
                stack.has_docker = True
                stack.detected_files.append(df)

        # CI/CD
        for ci_path in [
            ".github/workflows",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            "Jenkinsfile",
            ".travis.yml",
            "azure-pipelines.yml",
        ]:
            if (self.root / ci_path).exists():
                stack.has_ci = True
                stack.detected_files.append(ci_path)

        # TypeScript
        if (self.root / "tsconfig.json").exists():
            stack.has_typescript = True
            stack.detected_files.append("tsconfig.json")

        # Set primary language if not yet set
        if not stack.primary_language:
            if stack.runtime == "node":
                stack.primary_language = "TypeScript" if stack.has_typescript else "JavaScript"
            elif stack.runtime == "python":
                stack.primary_language = "Python"
            elif stack.runtime == "php":
                stack.primary_language = "PHP"

        return stack

    # ── Node.js detector ───────────────────────────────────────────────────────

    def _detect_node(self, path: Path, stack: StackInfo) -> None:
        try:
            data = json.loads(path.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        stack.runtime = "node"
        stack.detected_files.append("package.json")

        all_deps = {
            **data.get("dependencies", {}),
            **data.get("devDependencies", {}),
        }

        # Bun detection
        has_bun_lock = (self.root / "bun.lock").exists()
        has_bunfig = (self.root / "bunfig.toml").exists()
        has_bun_engine = data.get("engines", {}).get("bun") is not None
        if has_bun_lock or has_bunfig:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Bun",
                    language="JavaScript",
                    version="",
                    config_file="bun.lock" if has_bun_lock else "bunfig.toml",
                    confidence=0.95,
                )
            )
        elif has_bun_engine:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Bun",
                    language="JavaScript",
                    version="",
                    config_file="package.json",
                    confidence=0.80,
                )
            )

        # Package manager
        if (self.root / "bun.lock").exists():
            stack.package_manager = "bun"
        elif (self.root / "pnpm-lock.yaml").exists():
            stack.package_manager = "pnpm"
        elif (self.root / "yarn.lock").exists():
            stack.package_manager = "yarn"
        elif (self.root / "package-lock.json").exists():
            stack.package_manager = "npm"
        else:
            stack.package_manager = "npm"

        # Framework detection ordered by specificity
        fw_checks: list[tuple[str, str, str, list[str]]] = [
            # (framework_name, language, version_dep, indicator_deps)
            ("Next.js", "TypeScript", "next", ["next"]),
            ("Nuxt", "TypeScript", "nuxt", ["nuxt"]),
            ("SvelteKit", "TypeScript", "@sveltejs/kit", ["@sveltejs/kit"]),
            ("Remix", "TypeScript", "@remix-run/react", ["@remix-run/react"]),
            ("Astro", "TypeScript", "astro", ["astro"]),
            ("Solid.js", "TypeScript", "solid-js", ["solid-js"]),
            ("Qwik", "TypeScript", "@builder.io/qwik", ["@builder.io/qwik", "qwik"]),
            ("Preact", "JavaScript", "preact", ["preact"]),
            ("NestJS", "TypeScript", "@nestjs/core", ["@nestjs/core"]),
            ("Hono", "TypeScript", "hono", ["hono"]),
            ("tRPC", "TypeScript", "@trpc/server", ["@trpc/server", "@trpc/client"]),
            ("Express", "JavaScript", "express", ["express"]),
            ("Fastify", "JavaScript", "fastify", ["fastify"]),
            ("Koa", "JavaScript", "koa", ["koa"]),
            ("Hapi", "JavaScript", "hapi", ["@hapi/hapi", "hapi"]),
            ("React", "JavaScript", "react", ["react", "react-dom"]),
            ("Vue", "JavaScript", "vue", ["vue"]),
            ("Svelte", "JavaScript", "svelte", ["svelte"]),
            ("Angular", "TypeScript", "@angular/core", ["@angular/core"]),
            ("Electron", "JavaScript", "electron", ["electron"]),
            ("Vite", "JavaScript", "vite", ["vite"]),
        ]

        for fw_name, fw_lang, version_dep, indicators in fw_checks:
            if any(dep in all_deps for dep in indicators):
                version = _parse_semver(all_deps.get(version_dep, ""))
                stack.frameworks.append(
                    FrameworkInfo(
                        name=fw_name,
                        language=fw_lang,
                        version=version,
                        config_file="package.json",
                        confidence=0.95,
                    )
                )

        # Test framework
        test_frameworks = {
            "jest": "Jest",
            "vitest": "Vitest",
            "mocha": "Mocha",
            "jasmine": "Jasmine",
            "playwright": "Playwright",
            "cypress": "Cypress",
            "@testing-library/react": "Testing Library",
        }
        for dep, name in test_frameworks.items():
            if dep in all_deps:
                stack.test_framework = name
                break

        if stack.has_typescript or "typescript" in all_deps:
            stack.has_typescript = True

    # ── Python detector ────────────────────────────────────────────────────────

    def _detect_python(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "python"
        stack.detected_files.append(path.name)
        stack.package_manager = "pip"

        if (self.root / "Pipfile").exists():
            stack.package_manager = "pipenv"
        if (self.root / "poetry.lock").exists():
            stack.package_manager = "poetry"

        try:
            content = path.read_text("utf-8")
        except OSError:
            return

        fw_patterns: list[tuple[str, str, re.Pattern]] = [
            ("FastAPI", "Python", re.compile(r"fastapi", re.I)),
            ("Django", "Python", re.compile(r"django", re.I)),
            ("Flask", "Python", re.compile(r"flask", re.I)),
            ("Starlette", "Python", re.compile(r"starlette", re.I)),
            ("Tornado", "Python", re.compile(r"tornado", re.I)),
            ("Sanic", "Python", re.compile(r"sanic", re.I)),
            ("Litestar", "Python", re.compile(r"litestar", re.I)),
            ("aiohttp", "Python", re.compile(r"aiohttp", re.I)),
        ]

        for fw_name, fw_lang, pattern in fw_patterns:
            if pattern.search(content):
                version = _extract_version_from_requirements(content, fw_name.lower())
                stack.frameworks.append(
                    FrameworkInfo(
                        name=fw_name,
                        language=fw_lang,
                        version=version,
                        config_file=path.name,
                        confidence=0.90,
                    )
                )

        # Test framework
        if re.search(r"pytest", content, re.I):
            stack.test_framework = "pytest"
        elif re.search(r"unittest", content, re.I):
            stack.test_framework = "unittest"

        # pyproject.toml extra: primary language from [tool.poetry]
        if path.name == "pyproject.toml" and "[tool.poetry]" in content:
            stack.primary_language = "Python"

    # ── PHP detector ──────────────────────────────────────────────────────────

    def _detect_php(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "php"
        stack.package_manager = "composer"
        stack.detected_files.append("composer.json")

        try:
            data = json.loads(path.read_text("utf-8"))
        except (json.JSONDecodeError, OSError):
            return

        all_deps = {**data.get("require", {}), **data.get("require-dev", {})}

        if "laravel/framework" in all_deps:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Laravel",
                    language="PHP",
                    version=_parse_semver(all_deps.get("laravel/framework", "")),
                    config_file="composer.json",
                    confidence=0.99,
                )
            )
        if "symfony/symfony" in all_deps or "symfony/framework-bundle" in all_deps:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Symfony",
                    language="PHP",
                    version="",
                    config_file="composer.json",
                    confidence=0.95,
                )
            )
        if not stack.frameworks:
            # Bare PHP
            stack.frameworks.append(
                FrameworkInfo(
                    name="PHP",
                    language="PHP",
                    version="",
                    config_file="composer.json",
                    confidence=0.7,
                )
            )

    # ── Rust detector ─────────────────────────────────────────────────────────

    def _detect_rust(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "rust"
        stack.detected_files.append("Cargo.toml")
        stack.package_manager = "cargo"

        if (self.root / "Cargo.lock").exists():
            stack.detected_files.append("Cargo.lock")

        import tomllib

        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            _log.warning("FrameworkDetector._detect_rust failed: %s", e)
            data = {}

        deps = {**data.get("dependencies", {}), **data.get("build-dependencies", {})}
        if isinstance(deps, dict):
            all_deps = set(deps.keys())
        else:
            all_deps = set()

        workspace = data.get("workspace", {})
        members = workspace.get("members", [])
        if isinstance(members, list):
            for member in members:
                member_path = self.root / member / "Cargo.toml"
                if member_path.exists():
                    try:
                        with open(member_path, "rb") as f:
                            md = tomllib.load(f)
                        md_deps = (
                            set(md.get("dependencies", {}).keys())
                            if isinstance(md.get("dependencies"), dict)
                            else set()
                        )
                        all_deps.update(md_deps)
                    except Exception as e:
                        _log.warning("FrameworkDetector._detect_rust failed: %s", e)

        stack.primary_language = "Rust"

        # Rust framework detection
        fw_checks = [
            ("Actix Web", "Rust", ["actix-web", "actix-rt"]),
            ("Axum", "Rust", ["axum"]),
            ("Rocket", "Rust", ["rocket"]),
            ("Tauri", "Rust", ["tauri"]),
            ("Warp", "Rust", ["warp"]),
            ("Tokio", "Rust", ["tokio"]),
            ("Serde", "Rust", ["serde"]),
            ("Clap", "Rust", ["clap"]),
            ("SQLx", "Rust", ["sqlx"]),
            ("Diesel", "Rust", ["diesel"]),
            ("Reqwest", "Rust", ["reqwest"]),
        ]

        for fw_name, fw_lang, indicators in fw_checks:
            if any(dep in all_deps for dep in indicators):
                version = ""
                for ind in indicators:
                    dep_val = deps.get(ind, "")
                    if isinstance(dep_val, str) and dep_val:
                        version = dep_val.lstrip("^~>=< ").split()[0]
                        break
                    elif isinstance(dep_val, dict):
                        v = dep_val.get("version", "")
                        if v:
                            version = v.lstrip("^~>=< ").split()[0]
                            break
                stack.frameworks.append(
                    FrameworkInfo(
                        name=fw_name,
                        language=fw_lang,
                        version=version,
                        config_file="Cargo.toml",
                        confidence=0.95,
                    )
                )

        # Test framework
        if "rstest" in all_deps:
            stack.test_framework = "rstest"
        elif any("test" in d.lower() for d in all_deps):
            stack.test_framework = "cargo-test"

    # ── Java detector ───────────────────────────────────────────────────────

    def _detect_java(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "java"
        stack.detected_files.append(path.name)
        content = ""
        try:
            content = path.read_text("utf-8")
        except OSError:
            return

        if path.name == "pom.xml":
            stack.package_manager = "maven"
            import re

            # Detect Spring Boot from pom.xml
            if re.search(r"spring-boot-starter", content, re.I):
                version = ""
                vm = re.search(r"<spring-boot.version>([^<]+)", content)
                if vm:
                    version = vm.group(1)
                stack.frameworks.append(
                    FrameworkInfo(
                        name="Spring Boot",
                        language="Java",
                        version=version,
                        config_file=path.name,
                        confidence=0.95,
                    )
                )
            # Detect Quarkus from pom.xml
            elif re.search(r"quarkus-", content, re.I) or re.search(r"io\.quarkus", content):
                version = ""
                vm = re.search(r"<quarkus\.version>([^<]+)", content)
                if vm:
                    version = vm.group(1)
                stack.frameworks.append(
                    FrameworkInfo(
                        name="Quarkus",
                        language="Java",
                        version=version,
                        config_file=path.name,
                        confidence=0.95,
                    )
                )
            # Detect Micronaut from pom.xml
            elif re.search(r"micronaut-", content, re.I) or re.search(r"io\.micronaut", content):
                version = ""
                vm = re.search(r"<micronaut\.version>([^<]+)", content)
                if vm:
                    version = vm.group(1)
                stack.frameworks.append(
                    FrameworkInfo(
                        name="Micronaut",
                        language="Java",
                        version=version,
                        config_file=path.name,
                        confidence=0.95,
                    )
                )
        elif path.name.startswith("build.gradle"):
            stack.package_manager = "gradle"
            import re

            if "spring" in content.lower():
                stack.frameworks.append(
                    FrameworkInfo(
                        name="Spring Boot",
                        language="Java",
                        version="",
                        config_file=path.name,
                        confidence=0.90,
                    )
                )
            elif "quarkus" in content.lower():
                stack.frameworks.append(
                    FrameworkInfo(
                        name="Quarkus",
                        language="Java",
                        version="",
                        config_file=path.name,
                        confidence=0.90,
                    )
                )
            elif "micronaut" in content.lower():
                stack.frameworks.append(
                    FrameworkInfo(
                        name="Micronaut",
                        language="Java",
                        version="",
                        config_file=path.name,
                        confidence=0.90,
                    )
                )

        if not stack.frameworks:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Java", language="Java", version="", config_file=path.name, confidence=0.7
                )
            )

    # ── C# detector ─────────────────────────────────────────────────────────

    def _detect_csharp(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "dotnet"
        stack.package_manager = "nuget"
        stack.primary_language = "C#"
        stack.detected_files.append(path.name)
        content = ""
        try:
            content = path.read_text("utf-8")
        except OSError:
            return

        import re

        # ASP.NET Core: the Sdk attribute on <Project> is the most reliable signal
        # (e.g. Sdk="Microsoft.NET.Sdk.Web"), backed up by a package reference check
        # for older-style csproj files that don't set a Web Sdk explicitly.
        is_web_sdk = bool(re.search(r'Sdk\s*=\s*"Microsoft\.NET\.Sdk\.Web"', content, re.I))
        has_aspnet_ref = bool(re.search(r"Microsoft\.AspNetCore", content, re.I))

        if is_web_sdk or has_aspnet_ref:
            version = ""
            vm = re.search(r"<TargetFramework>net(\d+(?:\.\d+)?)", content, re.I)
            if vm:
                version = vm.group(1)
            stack.frameworks.append(
                FrameworkInfo(
                    name="ASP.NET Core",
                    language="C#",
                    version=version,
                    config_file=path.name,
                    confidence=0.95 if is_web_sdk else 0.85,
                )
            )
        elif re.search(r"Microsoft\.Maui", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name=".NET MAUI",
                    language="C#",
                    version="",
                    config_file=path.name,
                    confidence=0.9,
                )
            )
        elif re.search(r'Sdk\s*=\s*"Microsoft\.NET\.Sdk\.BlazorWebAssembly"', content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Blazor WebAssembly",
                    language="C#",
                    version="",
                    config_file=path.name,
                    confidence=0.95,
                )
            )

        if not stack.frameworks:
            stack.frameworks.append(
                FrameworkInfo(
                    name="C#", language="C#", version="", config_file=path.name, confidence=0.7
                )
            )

    # ── Go detector ─────────────────────────────────────────────────────────

    def _detect_go(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "go"
        stack.package_manager = "go-mod"
        stack.primary_language = "Go"
        stack.detected_files.append("go.mod")
        try:
            path.read_text("utf-8")
        except OSError:
            pass

        if (self.root / "go.sum").exists():
            stack.detected_files.append("go.sum")

        # Detect Go web frameworks from source files
        go_files = self._rglob("*.go")
        all_imports: set[str] = set()
        for gf in go_files[:50]:
            try:
                text = gf.read_text("utf-8", errors="ignore")
                for m in __import__("re").finditer(r'"([^"]+)"', text):
                    all_imports.add(m.group(1))
            except Exception as e:
                _log.warning("FrameworkDetector._detect_go failed: %s", e)

        fw_checks = [
            ("Gin", "Go", ["github.com/gin-gonic/gin"]),
            ("Echo", "Go", ["github.com/labstack/echo"]),
            ("Fiber", "Go", ["github.com/gofiber/fiber"]),
            ("Chi", "Go", ["github.com/go-chi/chi"]),
            ("Cobra", "Go", ["github.com/spf13/cobra"]),
            ("urfave/cli", "Go", ["github.com/urfave/cli"]),
        ]

        for fw_name, fw_lang, indicators in fw_checks:
            if any(dep in all_imports for dep in indicators):
                stack.frameworks.append(
                    FrameworkInfo(
                        name=fw_name,
                        language=fw_lang,
                        version="",
                        config_file="go.mod",
                        confidence=0.95,
                    )
                )

        if not stack.frameworks:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Go", language="Go", version="", config_file="go.mod", confidence=0.7
                )
            )

    # ── C/C++ detector ──────────────────────────────────────────────────────

    def _detect_c_cpp(self, path: Path, stack: StackInfo) -> None:
        lang = "C++" if path.name == "CMakeLists.txt" else "C"
        stack.runtime = "native"
        stack.primary_language = lang
        stack.package_manager = "cmake" if path.name == "CMakeLists.txt" else "make"
        stack.detected_files.append(path.name)

        found_cpp = bool(self._rglob("*.cpp") or self._rglob("*.cxx"))

        if found_cpp:
            stack.primary_language = "C++"
            try:
                content = path.read_text("utf-8", errors="ignore")
                if "crow" in content.lower():
                    stack.frameworks.append(
                        FrameworkInfo(
                            name="Crow",
                            language="C++",
                            version="",
                            config_file=path.name,
                            confidence=0.85,
                        )
                    )
                if "drogon" in content.lower():
                    stack.frameworks.append(
                        FrameworkInfo(
                            name="Drogon",
                            language="C++",
                            version="",
                            config_file=path.name,
                            confidence=0.85,
                        )
                    )
            except Exception as e:
                _log.warning("FrameworkDetector._detect_c_cpp failed: %s", e)

        if not stack.frameworks:
            stack.frameworks.append(
                FrameworkInfo(
                    name=lang, language=lang, version="", config_file=path.name, confidence=0.7
                )
            )

    # ── Swift detector ──────────────────────────────────────────────────────

    def _detect_swift(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "swift"
        stack.package_manager = "spm"
        stack.primary_language = "Swift"
        stack.detected_files.append("Package.swift")
        try:
            content = path.read_text("utf-8", errors="ignore")
        except OSError:
            content = ""

        if re.search(r"vapor", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Vapor",
                    language="Swift",
                    version="",
                    config_file="Package.swift",
                    confidence=0.95,
                )
            )
        if re.search(r"kitura", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Kitura",
                    language="Swift",
                    version="",
                    config_file="Package.swift",
                    confidence=0.90,
                )
            )
        if re.search(r"perfect", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Perfect",
                    language="Swift",
                    version="",
                    config_file="Package.swift",
                    confidence=0.85,
                )
            )
        if not stack.frameworks:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Swift",
                    language="Swift",
                    version="",
                    config_file="Package.swift",
                    confidence=0.7,
                )
            )

    # ── Ruby detector ───────────────────────────────────────────────────────

    def _detect_ruby(self, path: Path, stack: StackInfo) -> None:
        stack.runtime = "ruby"
        stack.package_manager = "bundler"
        stack.primary_language = "Ruby"
        stack.detected_files.append("Gemfile")
        try:
            content = path.read_text("utf-8", errors="ignore")
        except OSError:
            content = ""

        if re.search(r"rails", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Ruby on Rails",
                    language="Ruby",
                    version="",
                    config_file="Gemfile",
                    confidence=0.95,
                )
            )
        elif re.search(r"sinatra", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Sinatra",
                    language="Ruby",
                    version="",
                    config_file="Gemfile",
                    confidence=0.90,
                )
            )
        elif re.search(r"hanami", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Hanami",
                    language="Ruby",
                    version="",
                    config_file="Gemfile",
                    confidence=0.85,
                )
            )
        elif re.search(r"grape", content, re.I):
            stack.frameworks.append(
                FrameworkInfo(
                    name="Grape",
                    language="Ruby",
                    version="",
                    config_file="Gemfile",
                    confidence=0.85,
                )
            )
        else:
            # Scan .rb files for framework imports (fallback)
            rb_files = self._rglob("*.rb")
            for rb in rb_files[:30]:
                try:
                    text = rb.read_text("utf-8", errors="ignore")
                    if re.search(r"class\s+\w+\s*<\s*(Sinatra::Base|Grape::API)", text):
                        if "Sinatra" in text:
                            stack.frameworks.append(
                                FrameworkInfo(
                                    name="Sinatra",
                                    language="Ruby",
                                    version="",
                                    config_file=rb.name,
                                    confidence=0.85,
                                )
                            )
                        elif "Grape" in text:
                            stack.frameworks.append(
                                FrameworkInfo(
                                    name="Grape",
                                    language="Ruby",
                                    version="",
                                    config_file=rb.name,
                                    confidence=0.85,
                                )
                            )
                        break
                except Exception as e:
                    _log.warning("FrameworkDetector._detect_ruby failed: %s", e)

        if not stack.frameworks:
            stack.frameworks.append(
                FrameworkInfo(
                    name="Ruby", language="Ruby", version="", config_file="Gemfile", confidence=0.7
                )
            )


# ── Helpers ────────────────────────────────────────────────────────────────────


def _parse_semver(version_str: str) -> str:
    """Strip version prefix characters and return clean semver string."""
    return version_str.lstrip("^~>=<").split(" ")[0].strip() or ""


def _extract_version_from_requirements(content: str, package: str) -> str:
    """Try to find version from requirements.txt style content."""
    pattern = re.compile(
        rf"^{re.escape(package)}(?:\[.*?\])?[>=!~<]+([^\s#,]+)",
        re.IGNORECASE | re.MULTILINE,
    )
    m = pattern.search(content)
    return m.group(1) if m else ""
