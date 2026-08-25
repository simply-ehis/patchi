from patchi.core.brain.route_detector.base import BaseRouteDetector

_DETECTOR_REGISTRY: dict[str, type[BaseRouteDetector]] = {}


def register_detector(language: str):
    def decorator(cls: type[BaseRouteDetector]):
        _DETECTOR_REGISTRY[language] = cls
        return cls

    return decorator


def get_detector(language: str) -> BaseRouteDetector | None:
    cls = _DETECTOR_REGISTRY.get(language)
    if cls is None:
        return None
    return cls()


def detect_routes(language: str, content: str, file_path: str) -> list[dict]:
    detector = get_detector(language)
    if detector is None:
        return []
    return detector.detect(content, file_path)
