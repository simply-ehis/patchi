from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from patchi.core.brain.framework import StackInfo
    from patchi.core.brain.scanner import FileInfo


@dataclass
class RouteInfo:
    method: str
    path: str
    handler: str
    file: str
    line: int
    middleware: list[str] = field(default_factory=list)
    auth_required: bool | None = None
    framework: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "path": self.path,
            "handler": self.handler,
            "file": self.file,
            "line": self.line,
            "middleware": self.middleware,
            "auth_required": self.auth_required,
            "framework": self.framework,
        }


_LANG_FW_MAP: dict[str, set[str]] = {
    "python": {"FastAPI", "Flask", "Django", "Starlette"},
    "javascript": {"Express", "Fastify", "Next.js", "Nuxt", "SvelteKit"},
    "typescript": {"Express", "Fastify", "Next.js", "Nuxt", "SvelteKit"},
    "java": {"Spring Boot"},
    "go": {"Gin", "Echo", "Fiber"},
    "rust": {"Actix Web", "Axum", "Rocket"},
    "swift": {"Vapor"},
    "ruby": {"Ruby on Rails", "Sinatra", "Grape"},
    "php": {"Laravel"},
    "c_sharp": {"ASP.NET Core"},
}


class RouteMapper:
    def __init__(self, root: Path, stack: StackInfo):
        self.root = root
        self.stack = stack

    def extract(self, file_infos: list[FileInfo]) -> list[RouteInfo]:
        from patchi.core.brain.route_detector.csharp import CSharpRouteDetector
        from patchi.core.brain.route_detector.file_based import (
            NextJsRouteDetector,
            NuxtRouteDetector,
            SvelteKitRouteDetector,
        )
        from patchi.core.brain.route_detector.go import GoRouteDetector
        from patchi.core.brain.route_detector.java import JavaRouteDetector
        from patchi.core.brain.route_detector.javascript import JavaScriptRouteDetector
        from patchi.core.brain.route_detector.php import PhpRouteDetector
        from patchi.core.brain.route_detector.python import PythonRouteDetector
        from patchi.core.brain.route_detector.ruby import RubyRouteDetector
        from patchi.core.brain.route_detector.rust import RustRouteDetector
        from patchi.core.brain.route_detector.swift import SwiftRouteDetector

        active_fw = {f.name for f in self.stack.frameworks}

        # Map from language to list of (default_fw_str, route_dicts)
        detector_map: dict[str, list] = {}
        for lang, frameworks in _LANG_FW_MAP.items():
            matched = frameworks & active_fw
            if not matched:
                continue
            detectors = []
            if lang == "python":
                detectors.append(("", PythonRouteDetector()))
            elif lang in ("javascript", "typescript"):
                detectors.append(("", JavaScriptRouteDetector()))
                if "Next.js" in matched:
                    detectors.append(("Next.js", NextJsRouteDetector()))
                if "Nuxt" in matched:
                    detectors.append(("Nuxt", NuxtRouteDetector()))
                if "SvelteKit" in matched:
                    detectors.append(("SvelteKit", SvelteKitRouteDetector()))
            elif lang == "java":
                detectors.append(("", JavaRouteDetector()))
            elif lang == "go":
                detectors.append(("", GoRouteDetector()))
            elif lang == "rust":
                detectors.append(("", RustRouteDetector()))
            elif lang == "swift":
                detectors.append(("", SwiftRouteDetector()))
            elif lang == "ruby":
                detectors.append(("", RubyRouteDetector()))
            elif lang == "php":
                detectors.append(("", PhpRouteDetector()))
            elif lang == "c_sharp":
                detectors.append(("", CSharpRouteDetector()))
            if detectors:
                detector_map[lang] = detectors

        routes: list[RouteInfo] = []

        for fi in file_infos:
            lang = fi.language.value
            detectors = detector_map.get(lang)
            if not detectors:
                continue

            try:
                content = (self.root / fi.path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for _fw_prefix, detector in detectors:
                dicts = detector.detect(content, str(fi.path))
                for d in dicts:
                    routes.append(
                        RouteInfo(
                            method=d.get("method", "GET"),
                            path=d.get("path", "/"),
                            handler=d.get("handler", ""),
                            file=d.get("file", str(fi.path)),
                            line=d.get("line", 0),
                            middleware=d.get("middleware", []),
                            auth_required=d.get("auth_required"),
                            framework=d.get("framework", _fw_prefix),
                        )
                    )

        seen: set[tuple] = set()
        unique: list[RouteInfo] = []
        for r in routes:
            key = (r.method, r.path, r.file)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique


# ── Backward-compat extractors for tests ─────────────────────────────────────


def _extract_fastapi(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.python import PythonRouteDetector

    return [RouteInfo(**d) for d in PythonRouteDetector().detect(content, file_path)]


def _extract_flask(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.python import PythonRouteDetector

    return [RouteInfo(**d) for d in PythonRouteDetector().detect(content, file_path)]


def _extract_django(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.python import PythonRouteDetector

    return [RouteInfo(**d) for d in PythonRouteDetector().detect(content, file_path)]


def _extract_express(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.javascript import JavaScriptRouteDetector

    return [RouteInfo(**d) for d in JavaScriptRouteDetector().detect(content, file_path)]


def _extract_fastify(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.javascript import JavaScriptRouteDetector

    return [RouteInfo(**d) for d in JavaScriptRouteDetector().detect(content, file_path)]


def _extract_laravel(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.php import PhpRouteDetector

    return [RouteInfo(**d) for d in PhpRouteDetector().detect(content, file_path)]


def _extract_spring(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.java import JavaRouteDetector

    return [RouteInfo(**d) for d in JavaRouteDetector().detect(content, file_path)]


def _extract_gin(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.go import GoRouteDetector

    return [RouteInfo(**d) for d in GoRouteDetector().detect(content, file_path)]


def _extract_echo(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.go import GoRouteDetector

    return [RouteInfo(**d) for d in GoRouteDetector().detect(content, file_path)]


def _extract_fiber(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.go import GoRouteDetector

    return [RouteInfo(**d) for d in GoRouteDetector().detect(content, file_path)]


def _extract_actix(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.rust import RustRouteDetector

    return [RouteInfo(**d) for d in RustRouteDetector().detect(content, file_path)]


def _extract_axum(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.rust import RustRouteDetector

    return [RouteInfo(**d) for d in RustRouteDetector().detect(content, file_path)]


def _extract_rocket(content: str, file_path: str) -> list[RouteInfo]:
    routes = _extract_actix(content, file_path)
    for r in routes:
        r.framework = "Rocket"
    return routes


def _extract_vapor(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.swift import SwiftRouteDetector

    return [RouteInfo(**d) for d in SwiftRouteDetector().detect(content, file_path)]


def _extract_rails(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.ruby import RubyRouteDetector

    return [RouteInfo(**d) for d in RubyRouteDetector().detect(content, file_path)]


def _extract_sinatra(content: str, file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.ruby import RubyRouteDetector

    return [RouteInfo(**d) for d in RubyRouteDetector().detect(content, file_path)]


def _extract_grape(content: str, file_path: str) -> list[RouteInfo]:
    return _extract_sinatra(content, file_path)


def _extract_nextjs_file_routes(file_path: str, root: Path | None = None) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.file_based import NextJsRouteDetector

    return [RouteInfo(**d) for d in NextJsRouteDetector().detect("", file_path)]


def _extract_nuxt_file_routes(file_path: str, root: Path | None = None) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.file_based import NuxtRouteDetector

    return [RouteInfo(**d) for d in NuxtRouteDetector().detect("", file_path)]


def _extract_sveltekit_file_routes(file_path: str) -> list[RouteInfo]:
    from patchi.core.brain.route_detector.file_based import SvelteKitRouteDetector

    return [RouteInfo(**d) for d in SvelteKitRouteDetector().detect("", file_path)]
