import re
from pathlib import PurePosixPath

from patchi.core.brain.route_detector.base import BaseRouteDetector


class NextJsRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        p = PurePosixPath(file_path)
        parts = p.parts

        if "pages" in parts and "api" in parts:
            idx = parts.index("pages")
            path_parts = parts[idx + 1 :]
            url_path = "/" + "/".join(path_parts).replace("[", ":").replace("]", "")
            url_path = re.sub(r"\.(?:js|ts|jsx|tsx)$", "", url_path)
            if url_path.endswith("/index"):
                url_path = url_path[:-6] or "/"
            routes.append(
                self._make_route("ANY", url_path, p.stem, file_path, 1, framework="Next.js")
            )

        elif "app" in parts and p.stem in ("route", "page"):
            idx = parts.index("app")
            path_parts = [x for x in parts[idx + 1 : -1] if not x.startswith("(")]
            url_path = "/" + "/".join(path_parts).replace("[", ":").replace("]", "")
            if not url_path:
                url_path = "/"
            routes.append(
                self._make_route(
                    "ANY" if p.stem == "route" else "GET",
                    url_path,
                    p.stem,
                    file_path,
                    1,
                    framework="Next.js",
                )
            )

        return routes


class NuxtRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        p = PurePosixPath(file_path)
        if "pages" not in p.parts:
            return routes

        idx = p.parts.index("pages")
        path_parts = list(p.parts[idx + 1 :])
        stem = PurePosixPath(path_parts[-1]).stem if path_parts else ""
        path_parts[-1] = stem
        url_path = "/" + "/".join(path_parts).replace("[", ":").replace("]", "")
        if url_path.endswith("/index"):
            url_path = url_path[:-6] or "/"
        routes.append(self._make_route("GET", url_path, stem, file_path, 1, framework="Nuxt"))
        return routes


class SvelteKitRouteDetector(BaseRouteDetector):
    def detect(self, content: str, file_path: str) -> list[dict]:
        routes: list[dict] = []
        p = PurePosixPath(file_path)
        if "routes" not in p.parts:
            return routes

        idx = p.parts.index("routes")
        path_parts = [x for x in p.parts[idx + 1 : -1] if not x.startswith("(")]
        url_path = "/" + "/".join(path_parts).replace("[", ":").replace("]", "")
        if not url_path:
            url_path = "/"

        method = (
            "ANY" if (p.name.endswith("+server.ts") or p.name.endswith("+server.js")) else "GET"
        )
        routes.append(
            self._make_route(method, url_path, p.stem, file_path, 1, framework="SvelteKit")
        )
        return routes
