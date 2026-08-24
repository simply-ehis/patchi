from abc import ABC, abstractmethod


class BaseRouteDetector(ABC):
    @abstractmethod
    def detect(self, content: str, file_path: str) -> list[dict]:
        ...

    def _make_route(
        self,
        method: str,
        path: str,
        handler: str,
        file_path: str,
        line: int,
        framework: str = "",
        middleware: list[str] | None = None,
        auth_required: bool | None = None,
    ) -> dict:
        return {
            "method": method,
            "path": path,
            "handler": handler,
            "file": file_path,
            "line": line,
            "middleware": middleware or [],
            "auth_required": auth_required,
            "framework": framework,
        }

    def _path_from_parts(self, parts: list[str]) -> str:
        return "/" + "/".join(parts).replace("[", ":").replace("]", "")
