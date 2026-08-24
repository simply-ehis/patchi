"""
Type checker registry — dispatches to per-language type checkers.

Usage:
    from patchi.core.brain.type_checker import check_types
    findings = check_types(source, lang, file_path)
"""

from __future__ import annotations

from typing import Any

from ..languages import Lang


def check_types(source: str, lang: Lang, file_path: str) -> list[dict]:
    """Run the type checker for the given language. Returns list of findings."""
    checker = _get_checker(lang)
    if checker is None:
        return []
    return checker.check(source, file_path)


def _get_checker(lang: Lang) -> Any | None:
    if lang == Lang.TYPESCRIPT:
        from .typescript import TypeScriptChecker
        return TypeScriptChecker()
    if lang == Lang.PYTHON:
        from .python import PythonTypeChecker
        return PythonTypeChecker()
    if lang == Lang.JAVA:
        from .java import JavaTypeChecker
        return JavaTypeChecker()
    if lang == Lang.GO:
        from .go import GoTypeChecker
        return GoTypeChecker()
    if lang == Lang.RUST:
        from .rust import RustTypeChecker
        return RustTypeChecker()
    if lang == Lang.C_SHARP:
        from .csharp import CSharpTypeChecker
        return CSharpTypeChecker()
    if lang == Lang.KOTLIN:
        from .kotlin import KotlinTypeChecker
        return KotlinTypeChecker()
    if lang == Lang.SWIFT:
        from .swift import SwiftTypeChecker
        return SwiftTypeChecker()
    if lang == Lang.PHP:
        from .php import PHPTypeChecker
        return PHPTypeChecker()
    if lang == Lang.DART:
        from .dart import DartTypeChecker
        return DartTypeChecker()
    return None
